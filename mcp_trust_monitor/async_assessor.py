"""Cancellable Responses API adapter for the owned monitor's optional reviewer.

The legacy synchronous assessor remains unchanged. Native async requests do not
occupy an executor thread after monitor cancellation. Cancellation stops local
waiting; it does not prove the provider stopped processing or charging a request.
"""
from __future__ import annotations

import asyncio
import json
import math

from .assessor import DEFAULT_MODEL, ModelError, OpenAIAssessor, _usage_dict


class AsyncOpenAIAssessor(OpenAIAssessor):
    def __init__(self, api_key, model=DEFAULT_MODEL, *, timeout_seconds=90,
                 max_retries=0, client=None, **kwargs):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError('model request timeout must be positive and finite')
        if type(max_retries) is not int or max_retries < 0:
            raise ValueError('model retry count must be a nonnegative integer')
        if client is None:
            if not api_key:
                raise ModelError('configuration', 'OPENAI_API_KEY is not set')
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=api_key, timeout=timeout_seconds, max_retries=max_retries)
        super().__init__(api_key, model, timeout_seconds=timeout_seconds,
                         max_retries=max_retries, client=client, **kwargs)
        self.timeout_seconds = timeout_seconds

    async def assess(self, context, previous_tools, retrieved):
        self.last_response_id = self.last_model = self.last_usage = None
        # Input/integrity errors remain distinct from transport errors.
        request = dict(model=self.model, instructions=self.instructions,
            input=self.input_builder(context, previous_tools, retrieved),
            text={'format':{'type':'json_schema', 'name':'mcp_tool_assessment',
                            'schema':self.schema_builder(context.rule_ids), 'strict':True}},
            max_output_tokens=self.max_output_tokens, store=False)
        try:
            response = await asyncio.wait_for(self._client.responses.create(**request),
                                              timeout=self.timeout_seconds)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise ModelError('api_error', type(exc).__name__) from None
        self.last_response_id = getattr(response, 'id', None)
        self.last_model = getattr(response, 'model', None)
        self.last_usage = _usage_dict(getattr(response, 'usage', None))
        if getattr(response, 'status', None) != 'completed':
            raise ModelError('incomplete', 'response did not complete')
        texts = []
        for item in getattr(response, 'output', None) or []:
            if getattr(item, 'type', None) != 'message':
                continue
            for part in getattr(item, 'content', None) or []:
                kind = getattr(part, 'type', None)
                if kind == 'refusal':
                    raise ModelError('refusal', 'model refused the assessment')
                if kind == 'output_text':
                    texts.append(getattr(part, 'text', ''))
        text = ''.join(texts).strip()
        if not text:
            raise ModelError('empty', 'no output text')
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise ModelError('malformed', 'output is not JSON') from None

    async def aclose(self):
        await self._client.close()
