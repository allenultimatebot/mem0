import logging
import os
from typing import List

from app.utils.prompts import MEMORY_CATEGORIZATION_PROMPT
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel
from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()

# The categorizer is independent of mem0's config system. Point it at the same
# OpenAI-compatible gateway as the LLM (9router) via LLM_BASE_URL/LLM_API_KEY so
# it doesn't require a real OPENAI_API_KEY. Lazily instantiated so a missing key
# can never crash module import (which previously took down the whole API).
_openai_client = None


def _get_client() -> OpenAI:
    global _openai_client
    if _openai_client is None:
        base_url = os.environ.get("LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
        api_key = (
            os.environ.get("LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("API_KEY")
            or "not-needed"
        )
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        _openai_client = OpenAI(**kwargs)
    return _openai_client


# Model used for categorization. Defaults to the configured LLM so it routes
# through the same gateway; override with CATEGORIZATION_MODEL if desired.
_CATEGORIZATION_MODEL = os.environ.get("CATEGORIZATION_MODEL") or os.environ.get("LLM_MODEL") or "gpt-4o-mini"


class MemoryCategories(BaseModel):
    categories: List[str]


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=15))
def get_categories_for_memory(memory: str) -> List[str]:
    try:
        messages = [
            {"role": "system", "content": MEMORY_CATEGORIZATION_PROMPT},
            {"role": "user", "content": memory}
        ]

        # Let the gateway handle the pydantic parsing directly
        completion = _get_client().beta.chat.completions.parse(
            model=_CATEGORIZATION_MODEL,
            messages=messages,
            response_format=MemoryCategories,
            temperature=0
        )

        parsed: MemoryCategories = completion.choices[0].message.parsed
        return [cat.strip().lower() for cat in parsed.categories]

    except Exception as e:
        logging.error(f"[ERROR] Failed to get categories: {e}")
        try:
            logging.debug(f"[DEBUG] Raw response: {completion.choices[0].message.content}")
        except Exception as debug_e:
            logging.debug(f"[DEBUG] Could not extract raw response: {debug_e}")
        raise
