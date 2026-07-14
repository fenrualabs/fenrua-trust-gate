# Fuzzing Boundary

Parser and canonicalisation fuzz targets are planned for the later R2/R3 test
train. R1 unit tests cover bounded parsing, duplicate keys, Unicode surrogate
handling, canonical determinism, and canonicalisation bounds. Their presence is
not a claim that fuzzing has run or that the implementation has been audited.
