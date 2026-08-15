#!/usr/bin/env python3
"""Boucle 6 — migrer 5 méthodes de Logic vers self.repo dans email_impl.rs.

Chaque méthode existante contient :
    #[cfg(not(test))]
    { <mongodb direct code> }
    #[cfg(test)]
    { <stub> }

On remplace par un one-liner :
    self.repo.<method>(<args>).await
"""
import re
from pathlib import Path

P = Path("src/logic/email_impl.rs")
src = P.read_text()

def replace_method(src: str, method_name: str, new_body: str) -> str:
    """Trouve `pub async fn <method_name>(...)` et remplace son corps entier."""
    # Regex qui capture depuis "pub async fn METHOD" jusqu'à la fin du corps
    # Utilise un compteur d'accolades naïf
    idx = src.find(f"pub async fn {method_name}(")
    if idx < 0:
        raise RuntimeError(f"not found: {method_name}")
    # Trouver l'ouverture de corps `{` après la signature
    open_brace = src.index("{", src.index(")", idx))
    # Compter les accolades pour trouver la fermeture
    depth = 1
    i = open_brace + 1
    while depth > 0:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    close_brace = i  # position juste après le `}`
    # Le corps entre open_brace+1 et close_brace-1
    return src[:open_brace + 1] + "\n" + new_body + "\n    }" + src[close_brace:]

# Remplacements — chaque méthode devient un simple appel repo
src = replace_method(src, "get_emails_page", """        self.repo
            .get_emails_page(username, mailbox, limit, skip)
            .await""")

src = replace_method(src, "fetch_email", """        self.repo.fetch_email(username, email_id).await""")

src = replace_method(src, "move_email_to_mailbox", """        self.repo
            .move_email_to_mailbox(username, email_id, &mailbox.to_ascii_lowercase())
            .await""")

src = replace_method(src, "set_email_read", """        self.repo
            .set_email_read(username, email_id, is_read)
            .await""")

src = replace_method(src, "set_email_starred", """        self.repo
            .set_email_starred(username, email_id, is_starred)
            .await""")

P.write_text(src)
print("done")
