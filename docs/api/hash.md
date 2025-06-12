# Hashing

```python
from cydrogen import Hash, HashKey

DATA = b"data to hash"

# simple
d1 = Hash(data=DATA).digest()  # uses the zero key, default context
d2 = Hash(key="6kNVkds/wu9auUhPhMXzvwfsdW5Sq6SnYA095fBl+yU=", data=DATA).digest()

# Hash and HashKey classes
key = HashKey.gen()             # generate a random hash key
hasher = Hash(key=key)          # default context, default digest size
hasher.update(DATA)
hash_value = hasher.digest()    # 16 bytes

# you can choose the size of the digest
hasher = Hash(ctx="example", digest_size=32)    # uses the zero key
hasher.update(DATA)
assert len(hasher.digest()) == 32
```

## ::: cydrogen.HashKey
    options:
      heading: "class HashKey"
      show_root_heading: true
      inherited_members: true

## ::: cydrogen.Hash
    options:
      heading: "class Hash"
      show_root_heading: true

## ::: cydrogen.hash_file
    options:
      show_root_heading: true
