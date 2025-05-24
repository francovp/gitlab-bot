import os
import re
from typing import Optional


def get_summary_prompt_text(name: str, lang: str, custom_rule: Optional[str] = None) -> str:
    current_directory = os.path.dirname(os.path.realpath(__file__))
    file_name = f"{name}_en.txt"
    if lang is "zh":
        file_name = f"{name}_zh.txt"
    path = os.path.join(current_directory, file_name)
    with open(path, "r", encoding="UTF-8") as file:
        summary_prompt = file.read()
        if custom_rule:
            # replace summary_prompt_rule with the actual rule
            summary_prompt = re.sub(
                r"<RULES>.*?</RULES>",
                f"{custom_rule}",
                summary_prompt,
                flags=re.DOTALL,
            )
        else:
            # Remove the tags
            summary_prompt = summary_prompt.replace("<RULES>\n", "").replace("</RULES>\n", "")

        # Add language-specific instruction at the end
        lang_map = {
            "es": "spanish",
            "en": "english",
            "zh": "chinese"
        }
        language_text = lang_map.get(lang, lang)
        summary_prompt = summary_prompt.rstrip() + f"\n\nRespond in {language_text}"
        return summary_prompt
