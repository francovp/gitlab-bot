��          |      �             !     2     E     _     x     �     �     �     �     �     �      B   )  4   l  ;   �  �   �  3   o  \   �  �         �     �  "   �  ,   �     	                                        
              bot_review_fails bot_review_success commit_subject_max_length email_username_not_match invalid_bot_action invalid_commit_message invalid_email_address issue_num_is_required milestone_is_required milestone_not_found milestone_release_note Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: 
PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE
Last-Translator: FULL NAME <EMAIL@ADDRESS>
Language-Team: LANGUAGE <LL@li.org>
Language: zh
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
 💔合并请求验证失败，并撤回批准。

{error_message} 😊合并请求验证成功，批准合并请求。 主题行不能超过 {commit_subject_max_length} 个字符 邮箱用户名与邮箱地址不匹配，请确定邮箱用户名 "{commit_author_name}" 与邮箱地址 "{commit_author_email}" 是否匹配。 无效的指令，正确的指令格式是 {action} 无效的提示消息标题 '{commit_msg}'， 例如:

{git_commit_subject_example_markdown} 无效的用户邮箱地址 "{commit_author_email}"。 必须使用来自 "@{gitlab_email_domain}" 域的邮箱， 请提供设置正确的用户邮箱地址。 请至少关联一个问题 必须选择里程碑 里程碑 {milestone} 没有找到 里程碑 {milestone} 发布说明: 
{notes} 