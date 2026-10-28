from textual.command import Provider, Hit, Hits

class TorkCommandProvider(Provider):
    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)

        title_copy = "Copy My Onion ID"
        score_copy = matcher.match(title_copy) if query else 0
        if not query or score_copy > 0:
            yield Hit(
                score_copy if query else 1.0,
                matcher.highlight(title_copy) if query else title_copy,
                self.app.action_copy_onion_id,
                help="Copy your 56-character Onion ID (without .onion suffix) to system clipboard",
            )

        title_add = "Add Contact"
        score_add = matcher.match(title_add) if query else 0
        if not query or score_add > 0:
            yield Hit(
                score_add if query else 1.0,
                matcher.highlight(title_add) if query else title_add,
                self.app.action_prompt_add_contact,
                help="Add a contact by pasting their 56-character onion hash (nickname auto-syncs)",
            )
