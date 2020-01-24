# functionalSha512
sha512 python implementation using only immutable inputs and stateless functions.

# What? Why?
One of the originators of Excel:s built-in encryption mentioned that it's actually very brute-force resistant. He is/was right - it employs 100k cycles of sha512 prior to using a password, massively stalling crack attempts. Realizing I don't really know much about sha512 (besides that it's like sha256, but 64 bit, and several more differences) I wondered a bit if repeating it is prone to dependency lopps/cycles or other "simplifyable" calculations, in this special case or ever. Since it worked pretty well with TOTP, decided to rewrite it from specs in pure functions (no mutables or states), which is also a good opportunity to shake the dust off not-so-frequently-used functional skills, should they be needed again.
