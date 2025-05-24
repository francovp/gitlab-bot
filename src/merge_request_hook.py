# Copyright 2023 Lei Zhang
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import logging
import re
from enum import Enum
import json

from src.config import (
    bot_git_commit_message_check_enabled,
    bot_git_commit_subject_example_markdown,
    bot_git_commit_subject_max_length,
    bot_git_commit_subject_regex,
    bot_git_email_domain,
    bot_gitlab_merge_request_aireview_label_enabled,
    bot_gitlab_merge_request_approval_enabled,
    bot_gitlab_merge_request_email_username_not_match_enabled,
    bot_gitlab_merge_request_issue_required,
    bot_gitlab_merge_request_milestone_required,
    bot_gitlab_merge_request_summary_enabled,
    bot_gitlab_username,
)
from src.i18n import _
from src.llm import AI, ai_diffs_summary


class StatusLabel(Enum):
    AIReview = "MRStatus::AIReview"


class StatusLabelAction(Enum):
    Add = "add"
    Remove = "remove"


all_status_labels = list(StatusLabel)


def check_changes(gl, project_id, iid):
    # url = f"/projects/{project_id}/merge_requests/{iid}/changes"
    # changes = await gl.getitem(url)
    # for change in changes:
    pass


def check_commit_message(commit_msg):
    if not bot_git_commit_message_check_enabled:
        return
    if len(commit_msg) > bot_git_commit_subject_max_length:
        raise Exception(
            _("commit_subject_max_length").format(commit_subject_max_length=bot_git_commit_subject_max_length)
        )
    if commit_msg.startswith("Merge branch "):
        return
    regex = re.compile(bot_git_commit_subject_regex)
    if re.search(regex, commit_msg) is None:
        raise Exception(
            _("invalid_commit_message").format(
                commit_msg=commit_msg,
                git_commit_subject_example_markdown=bot_git_commit_subject_example_markdown,
            )
        )


def check_description(description):
    if bot_gitlab_merge_request_issue_required:
        issue_num_pattern = r"(#\d+)"
        if not re.search(issue_num_pattern, description):
            raise Exception(_("issue_num_is_required"))


def check_milestone(milestone_id):
    if bot_gitlab_merge_request_milestone_required and milestone_id is None:
        raise Exception(_("milestone_is_required"))


def check_email(commit_author_name, commit_author_email):
    if bot_git_email_domain is not None:
        username, domain = commit_author_email.split("@")
        if domain != bot_git_email_domain:
            raise Exception(
                _("invalid_email_address").format(
                    commit_author_email=commit_author_email,
                    gitlab_email_domain=bot_git_email_domain,
                )
            )
        if bot_gitlab_merge_request_email_username_not_match_enabled and username != commit_author_name:
            raise Exception(
                _("email_username_not_match").format(
                    commit_author_name=commit_author_name,
                    commit_author_email=commit_author_email,
                )
            )


# Helper function to parse a single file's diff string
def parse_diff_lines(diff_content: str):
    lines_info = []
    old_line_num = 0
    new_line_num = 0
    in_hunk = False

    # Split diff content into lines and iterate
    for line in diff_content.splitlines():
        # Check for hunk header (e.g., @@ -1,5 +1,5 @@)
        hunk_match = re.match('@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
        if hunk_match:
            # The hunk header numbers are 1-based, initialize counters based on them
            old_line_num = int(hunk_match.group(1)) - 1
            new_line_num = int(hunk_match.group(2)) - 1
            in_hunk = True
            continue # Skip the hunk header line

        if in_hunk:
            # Added line
            if line.startswith('+'):
                new_line_num += 1
                lines_info.append({'type': 'added', 'old_line': None, 'new_line': new_line_num, 'content': line[1:]})
            # Removed line
            elif line.startswith('-'):
                old_line_num += 1
                lines_info.append({'type': 'removed', 'old_line': old_line_num, 'new_line': None, 'content': line[1:]})
            # Context or modified line
            elif line.startswith(' '):
                old_line_num += 1
                new_line_num += 1
                # We can't distinguish modified from unchanged context lines without more complex parsing
                # For positioning, context lines are treated as unchanged.
                lines_info.append({'type': 'unchanged', 'old_line': old_line_num, 'new_line': new_line_num, 'content': line[1:]})
            # No-newline-at-end-of-file marker or other diff syntax - ignore for line numbers
            elif line.startswith('\\'):
                 pass
            # Handle potential deviations from standard hunk format (basic error handling)
            else:
                logging.warning(f"Unexpected line format in diff hunk: {line[:50]}...")
                # Attempt to continue by incrementing both, though this is uncertain
                old_line_num += 1
                new_line_num += 1

    return lines_info


def parse_ai_suggestions(response_summary, diffs):
    suggestions = []
    try:
        # Attempt to find and parse JSON within the response string
        # Assumes the JSON is a single block, potentially with surrounding text
        json_match = re.search(r'```json\n(.*)\n```', response_summary, re.DOTALL)
        if json_match:
            json_content = json_match.group(1)
            parsed_suggestions = json.loads(json_content)
        else:
            # If no code block, try parsing the whole response as JSON
            parsed_suggestions = json.loads(response_summary)

        # Validate the structure and extract suggestions
        if isinstance(parsed_suggestions, list):
            for suggestion_data in parsed_suggestions:
                if isinstance(suggestion_data, dict):
                    file_path = suggestion_data.get('file_path')
                    line_number = suggestion_data.get('line_number') # For single line suggestions
                    start_line = suggestion_data.get('start_line') # For multi-line suggestions
                    end_line = suggestion_data.get('end_line') # For multi-line suggestions
                    comment_body = suggestion_data.get('comment')

                    if comment_body is not None:
                        # Find the corresponding diff for the file path (if file_path is provided)
                        target_diff = None
                        if file_path:
                            for diff in diffs:
                                if diff.get('new_path') == file_path or diff.get('old_path') == file_path:
                                    target_diff = diff
                                    break

                        suggestions.append({
                            "file_path": file_path,
                            "line_number": line_number, # Keep for single line for now
                            "start_line": start_line, # Add for multi-line
                            "end_line": end_line, # Add for multi-line
                            "comment_body": comment_body,
                            "diff": target_diff # Keep diff reference for SHAs and paths
                        })
                    else:
                        logging.warning("Skipping suggestion with missing comment body.")
                else:
                    logging.warning("Skipping non-object item in AI suggestions list.")
        else:
            logging.warning("AI response is not a JSON array.")

    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse AI response as JSON: {e}")
        # Optionally, treat the whole response as a general summary if JSON parsing fails
        suggestions.append({
            "file_path": "", # Indicates overall diff comment
            "line_number": None,
            "comment_body": response_summary,
            "diff": None
        })
    except Exception as e:
        logging.error(f"An error occurred while parsing AI suggestions: {e}")
        # Fallback to general summary
        suggestions.append({
            "file_path": "", # Indicates overall diff comment
            "line_number": None,
            "comment_body": response_summary,
            "diff": None
        })

    return suggestions


async def generate_diff_description_summary(event, gl):
    project_id = event.project_id
    description = event.data["object_attributes"]["description"]
    labels = event.data["object_attributes"]["labels"]
    iid = event.data["object_attributes"]["iid"]
    change_event = event.data["changes"]
    if not change_event:
        logging.debug("MR has no code changes, AI Summary generation skipped...")
        return None
    
    if bot_gitlab_merge_request_summary_enabled and AI is not None:
        
        # Check if an AI review is already present (based on description or label)
        if has_ai_review(description, labels):
            logging.debug("AI Summary/Review found, skipping generation...")
            return
        logging.debug("Generating AI Summary/Review...")

        # Fetch commit SHAs from the latest merge request version as recommended by docs.
        base_commit_sha = None
        head_commit_sha = None
        start_commit_sha = None

        versions_url = f"/projects/{project_id}/merge_requests/{iid}/versions"
        logging.debug(f"Fetching versions from {versions_url}")
        
        try:
            versions_response = await gl.getitem(versions_url)
            logging.debug(f"Fetched versions from {versions_url}")

            if isinstance(versions_response, list) and versions_response:
                latest_version = versions_response[0]
                if isinstance(latest_version, dict):
                    base_commit_sha = latest_version.get('base_commit_sha')
                    head_commit_sha = latest_version.get('head_commit_sha')
                    start_commit_sha = latest_version.get('start_commit_sha')
                    logging.debug(f"Extracted SHAs from latest version: base={base_commit_sha}, head={head_commit_sha}, start={start_commit_sha}")
                else:
                    logging.warning("Latest version object is not a dictionary.")
            else:
                logging.warning("Versions API response is not a list or is empty.")

        except Exception as e:
            logging.error(f"Error calling API {versions_url} to fetch versions: {e}")
            return None

        # If head_commit_sha wasn't found in versions, try getting it from the event data as a fallback
        if head_commit_sha is None:
            try:
                # Attempt to get head_commit_sha from event data
                if event.data["event_type"] == "merge_request":
                    head_commit_sha = event.data["object_attributes"]["last_commit"]["id"]
                elif event.data["event_type"] == "note":
                    head_commit_sha = event.data["merge_request"]["last_commit"]["id"]
                if head_commit_sha:
                    logging.debug(f"Retrieved head_commit_sha from event data: {head_commit_sha}")
                else:
                    logging.warning("Head commit SHA not found in event data.")
            except Exception as e:
                logging.warning(f"Could not retrieve head_commit_sha from event data: {e}")


        # Fetch full diffs to get file paths and diff content
        diffs = []
        diffs_response = None
        diff_url = f"/projects/{project_id}/merge_requests/{iid}/diffs"

        try:
            # Fetch diffs - expecting a list of diff objects
            diffs_response = await gl.getitem(diff_url)
            logging.debug(f"Fetched diffs from {diff_url}")

        except Exception as e:
            logging.error(f"Error calling API {diff_url} to fetch diffs: {e}")
            # If fetching diffs fails, diffs_response remains None, handled below.

        # Process the API response - expecting a list
        if isinstance(diffs_response, list):
            # Response is a list of diff objects
            diffs = diffs_response
            logging.debug(f"API response is a list, extracted {len(diffs)} diff items.")
            # SHAs are now obtained from /versions, no need to extract from diff items here.

        else:
            logging.warning("API response is not a list as expected for diffs.")


        # Ensure we have diffs to proceed with AI summary generation
        if not diffs:
            logging.debug("MR has no diffs or failed to fetch diffs, AI Summary generation skipped...")
            return None

        # We need head_commit_sha for generating line_codes for line-specific comments
        # base_commit_sha and start_commit_sha are needed for the position object

        # If we still don't have head_commit_sha, we cannot create line-specific discussions.
        if head_commit_sha is None:
            logging.warning("Cannot proceed with line-specific discussions: Head commit SHA is not available after checking versions and event data.")
            # We will proceed with AI summary generation, but line-specific comments will be skipped.

        try:
            # Get AI response (expecting JSON)
            response_summary = ai_diffs_summary(diffs)

            # Parse AI suggestions from JSON
            suggestions = parse_ai_suggestions(response_summary, diffs)

            # Process suggestions and create discussions/notes
            general_summary_parts = []
            for suggestion in suggestions:
                parsed_lines = []
                # Check for insufficient data before attempting to create a discussion
                file_path = suggestion.get('file_path')
                line_number = suggestion.get('line_number')
                comment_body = suggestion.get('comment_body')
                diff_dict = suggestion.get('diff')
                diff = diff_dict.get('diff') if diff_dict else ""

                if not comment_body:
                    logging.warning(f"Skipping suggestion with missing comment body: {suggestion}")
                    continue # Skip suggestions without a comment body

                if diff:
                    # Parse the diff content to get line numbers
                    parsed_lines = parse_diff_lines(diff)
                else:
                    # Check if this is an overall diff comment
                    if file_path == "" and line_number is None and comment_body:
                        # Add to general summary queue
                        general_summary_parts.append(comment_body)
                        logging.debug("Queued overall diff comment.")
                        continue # Skip to next suggestion
                    else:
                        logging.warning(f"Skipping suggestion for {file_path}: suggestion does not match expected format.")
                        continue # Skip if no diff content

                # Find the line(s) in the parsed diff that match the AI's suggestion
                target_lines_info = []
                if suggestion.get('line_number') is not None:
                    # Single line suggestion (AI provides new line number)
                    target_new_line = suggestion.get('line_number')
                    for line_info in parsed_lines:
                        if line_info.get('new_line') == target_new_line:
                            target_lines_info.append(line_info)
                            # For a single line comment, the range starts and ends at the same line
                            break # Found the target line

                elif suggestion.get('start_line') is not None and suggestion.get('end_line') is not None:
                    # Multi-line suggestion (AI provides new line numbers for range)
                    target_start_new_line = suggestion.get('start_line')
                    target_end_new_line = suggestion.get('end_line')
                    # Find all lines within the suggested range in the new file
                    for line_info in parsed_lines:
                        if line_info.get('new_line') is not None and target_start_new_line <= line_info.get('new_line') <= target_end_new_line:
                            target_lines_info.append(line_info)
                    # Sort by new line number to ensure correct range order
                    target_lines_info.sort(key=lambda x: x.get('new_line', 0))

                # If we found matching lines in the diff
                if target_lines_info:
                    # Check if any of the lines have new_line values (we can only comment on lines that exist in the new version)
                    has_new_lines = any(li.get('new_line') is not None for li in target_lines_info)
                    
                    if has_new_lines:
                        # Only handle lines that exist in the new file (added or modified)
                        # Filter to only include lines with new_line values
                        valid_lines = [li for li in target_lines_info if li.get('new_line') is not None]
                        if not valid_lines:
                            logging.debug(f"No commentable lines found for {file_path}")
                            continue  # Skip if no valid lines after filtering
                            
                        start_line_info = valid_lines[0]  # First valid line in the range
                        end_line_info = valid_lines[-1]  # Last valid line in the range

                        # Get new line numbers for the range
                        start_line_new = start_line_info.get('new_line')
                        end_line_new = end_line_info.get('new_line')
                        # For old line numbers, if they're None (added lines), we'll use None
                        start_line_old = start_line_info.get('old_line')  # May be None for added lines
                        end_line_old = end_line_info.get('old_line')      # May be None for added lines

                        # Generate line_codes based on what data we have
                        if head_commit_sha:
                            # Generate SHA1 hash of the filename for line_code
                            file_path_sha = hashlib.sha1(diff_dict.get('new_path').encode()).hexdigest()
                            # For added lines, use 0 for old_line, for modified use actual old_line number
                            old_line_start = start_line_old if start_line_old is not None else 0
                            old_line_end = end_line_old if end_line_old is not None else 0
                            line_code_start = f"{file_path_sha}_{old_line_start}_{start_line_new}"
                            line_code_end = f"{file_path_sha}_{old_line_end}_{end_line_new}"
                        else:
                            logging.warning("Head commit SHA not available, cannot generate line_codes for line comment.")
                            continue # Skip this suggestion

                        # Construct position for added or modified line(s)
                        position = {
                            "position_type": "text",
                            "base_sha": base_commit_sha,
                            "head_sha": head_commit_sha,
                            "start_sha": start_commit_sha,
                            "new_path": diff_dict.get('new_path'),
                            "old_path": diff_dict.get('old_path'),
                            "new_line": end_line_new, # Top-level new_line is end of range
                            "old_line": end_line_old, # May be None for added lines
                            "line_range": {
                                "start": {
                                    "line_code": line_code_start,
                                    "type": "new"
                                    # new_line and old_line are only supported in GitLab 18.x+
                                },
                                "end": {
                                    "line_code": line_code_end,
                                    "type": "new"
                                    # new_line and old_line are only supported in GitLab 18.x+
                                }
                            }
                        }

                        # Create discussion
                        discussions_url = f"/projects/{project_id}/merge_requests/{iid}/discussions"
                        await gl.post(
                            discussions_url,
                            data={
                                "body": comment_body,
                                "position": position
                            },
                        )
                        
                        # Log with appropriate message based on what we have
                        if all(li.get('type') == 'added' for li in valid_lines):
                            logging.debug(f"Created discussion for added line(s) {file_path}:{start_line_new}-{end_line_new}")
                        else:
                            logging.debug(f"Created discussion for modified/unchanged line(s) {file_path}:{start_line_new}-{end_line_new}")
                    else:
                        # Skip comments for lines that don't exist in the new version (all removed)
                        logging.debug(f"Skipping comment for {file_path} as all lines in range were removed (nothing to comment on).")
                        continue

                else:
                    logging.warning(f"Skipping suggestion with insufficient data: {suggestion}")

                # Post any overall diff comments as a single note
                if general_summary_parts:
                    overall_summary_body = "AI Summary:\n\n" + "\n---\n".join(general_summary_parts)
                    merge_request_post_note_url = f"/projects/{project_id}/merge_requests/{iid}/notes"
                    await gl.post(
                        merge_request_post_note_url,
                        data={"body": overall_summary_body},
                    )
                    logging.debug("Posted overall AI summary as a note.")

                logging.debug("AI suggestions processed.")

            # Add AI Review status label if not exists
            if bot_gitlab_merge_request_aireview_label_enabled and not has_ai_review_label(labels):
                await update_status_label(
                    gl,
                    project_id,
                    iid,
                    StatusLabel.AIReview.value,
                    labels,
                    StatusLabelAction.Add,
                )
                logging.debug("AI Review status label added to MR.")
            
            return True

        except Exception as e:
            logging.error(f"Error during AI summary generation and discussion creation: {e}")
            # Re-raise the exception if necessary to indicate failure
            raise e
    else:
        logging.debug("AI Summary generation feature is disabled or AI feature is not available.")
        # Remove AI Review status label if the feature is disabled
        await update_status_label(
            gl,
            project_id,
            iid,
            StatusLabel.AIReview.value,
            labels,
            StatusLabelAction.Remove,
        )


async def check_commit(event, gl):
    project_id = event.project_id
    if event.data["event_type"] == "note":
        commit_title = event.data["merge_request"]["last_commit"]["title"]
        commit_author_name = event.data["merge_request"]["last_commit"]["author"]["name"]
        commit_author_email = event.data["merge_request"]["last_commit"]["author"]["email"]
        iid = event.data["merge_request"]["iid"]
        milestone_id = event.data["merge_request"]["milestone_id"]
        # source_branch = event.data["merge_request"]["source_branch"]
        description = event.data["merge_request"]["description"]
    elif event.data["event_type"] == "merge_request":
        commit_title = event.data["object_attributes"]["last_commit"]["title"]
        commit_author_name = event.data["object_attributes"]["last_commit"]["author"]["name"]
        commit_author_email = event.data["object_attributes"]["last_commit"]["author"]["email"]
        iid = event.data["object_attributes"]["iid"]
        milestone_id = event.data["object_attributes"]["milestone_id"]
        # source_branch = event.data["object_attributes"]["source_branch"]
        description = event.data["object_attributes"]["description"]

    merge_request_post_note_url = f"/projects/{project_id}/merge_requests/{iid}/notes"
    try:
        check_email(commit_author_name, commit_author_email)
        check_commit_message(commit_title)
        check_milestone(milestone_id)
        check_description(description)
        check_changes(gl, project_id, iid)
        url = f"/projects/{project_id}/merge_requests/{iid}/commits"
        commits = await gl.getitem(url)
        for commit in commits:
            commit_title = commit["title"]
            commit_author_name = commit["author_name"]
            commit_author_email = commit["author_email"]
            check_email(commit_author_name, commit_author_email)
            check_commit_message(commit_title)
        if bot_gitlab_merge_request_approval_enabled:
            message = _("bot_review_success")
            approval_merge_request(project_id, iid, gl)
            await gl.post(merge_request_post_note_url, data={"body": message})
    except Exception as e:
        message = _("bot_review_fails").format(error_message=str(e))
        await gl.post(merge_request_post_note_url, data={"body": message})

        # Only support GitLab Premium in 13.9
        # https://docs.gitlab.com/ee/api/merge_request_approvals.html#unapprove-merge-request
        # merge_request_post_unapproval_url = (
        #     f"/projects/{project_id}/merge_requests/{iid}/unapprove"
        # )
        # await gl.post(merge_request_post_unapproval_url, data=None)


async def approval_merge_request(project_id, iid, gl):
    query_approvals_url = f"/projects/{project_id}/merge_requests/{iid}/approvals"
    approvals = gl.getitem(query_approvals_url)
    bot_approved = False
    if approvals.approved:
        for approval in approvals.approved_by:
            if approval.user.username == bot_gitlab_username:
                bot_approved = True
                return
    if not bot_approved:
        await gl.post(f"/projects/{project_id}/merge_requests/{iid}/approve", data=None)


def is_opened_merge_request(event):
    if event.data["event_type"] == "merge_request":
        merge_request_state = event.data["object_attributes"]["state"]
    else:
        merge_request_state = event.data["merge_request"]["state"]
    return merge_request_state == "opened"


async def update_status_label(gl, pid, mr_iid, label, current_labels, action=StatusLabelAction.Add):
    if not is_status_label(label):
        logging.error(f"Label '{label}' is not a valid status label")
        return False, None
    to_update = [mr_label["title"] for mr_label in current_labels]
    if action == StatusLabelAction.Add:
        if label not in to_update:
            to_update.append(label)
            logging.debug(f"Adding status label '{label}' to MR {mr_iid}")
        else:
            logging.debug(f"Status label '{label}' already exists in MR {mr_iid}")
            return False, None
    elif action == StatusLabelAction.Remove:
        if label in to_update:
            to_update.remove(label)
            logging.debug(f"Removing status label '{label}' from MR {mr_iid}")
        else:
            logging.debug(f"Status label '{label}' does not exist in MR {mr_iid}")
            return False, None
    else:
        logging.error(f"Invalid action '{action}' for updating status label")
        return False, None
    await gl.put(
        f"/projects/{pid}/merge_requests/{mr_iid}?labels={','.join(to_update)}",
        data=None,
    )
    logging.debug(f"MR {mr_iid} labels updated successfully")
    return True, None


def is_status_label(label):
    for status in all_status_labels:
        logging.debug(f"Checking label '{label}' against {status}")
        if label == status.value:
            return True
    return False


def has_ai_review(description, labels):
    if bot_gitlab_merge_request_aireview_label_enabled and has_ai_review_label(labels):
        return True
    if has_ai_summary_description(description):
        return True
    return False


def has_ai_summary_description(description):
    if "AI Summary:" in description:
        return True
    return False


def has_ai_review_label(labels):
    for label in labels:
        if label["title"] == StatusLabel.AIReview.value:
            return True
    return False


class MergeRequestHooks:
    async def merge_request_opened_event(self, event, gl, *args, **kwargs):
        await generate_diff_description_summary(event, gl)
        await check_commit(event, gl)

    async def merge_request_updated_event(self, event, gl, *args, **kwargs):
        if is_opened_merge_request(event):
            await generate_diff_description_summary(event, gl)
            await check_commit(event, gl)

    async def merge_request_reopen_event(self, event, gl, *args, **kwargs):
        await generate_diff_description_summary(event, gl)
        await check_commit(event, gl)

    async def note_merge_request_event(self, event, gl, *args, **kwargs):
        if is_opened_merge_request(event):
            if "/bot-review" in event.data["object_attributes"]["note"]:
                await check_commit(event, gl)
