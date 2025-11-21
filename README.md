# AES-128 CBC - Crypt and decrypt strings or buffers in Game Maker 2 safely

**Example:**

```gml
var aes = new AES();

// STRING:
var encryptedStr = aes.encryptString("Hello world", "Safe password12345@") // Output encoded in base64
var decryptedStr = aes.decryptString(encryptedStr, "Safe password12345@")
show_debug_message(decryptedStr) // Hello world

// BUFFER:
var buf = buffer_create(12, buffer_fixed, 1);
buffer_write(buf, buffer_text, "Hello world!");
var encryptedBuffer = aes.encrypt(buf, "myPassword");
var decryptedBuffer = aes.decrypt(encryptedBuffer, "myPassword");
show_debug_message(buffer_read(decryptedBuffer, buffer_text))
```

## LICENSE

MIT
