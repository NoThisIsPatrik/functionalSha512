# functionalSha512
sha512 python implementation using only immutable inputs and stateless functions.

# What? Why?
One of the originators of Excel:s built-in encryption mentioned that it's actually very brute-force resistant. He is/was right - it employs 100k cycles of sha512 prior to using a password, massively stalling crack attempts. Realizing I don't really know much about sha512 (besides that it's like sha256, but 64 bit, and several more differences) I wondered a bit if repeating it is prone to dependency lopps/cycles or other "simplifyable" calculations, in this special case or ever. Since it worked pretty well with TOTP, decided to rewrite it from specs in pure functions (no mutables or states), which is also a good opportunity to shake the dust off not-so-frequently-used functional skills, should they be needed again.
# Files
sha512_func.py is the "original", heavily commented (in no small part to myself if I later need to know sha512 innards) version.

sha512_func_noc.py is *almost* the same thing, but without the comments - some of it is so over-commented that it's kind of hard to actually read the code.

sha512_compact.py is a refactored version with only four functions. The reason it is four instead of one is that all of them are of the form "f(x) = f( \[inline processing of x\] ) if not \[end condition\] else x". It's totally possible to refactor two functions like that into a single one (and I may do so), but the complexity goes up a bit, and the (already abysmal) readabillity is even further destroyed.
