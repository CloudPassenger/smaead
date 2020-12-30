# Student Main's broken AEAD

These AEAD implementation is used to decrypt cipher text without verify tag. 
It's purpose is provided a preview to long cipher text. 
DO NOT USE it's output as final result, use a real AEAD implementation to verify its result.