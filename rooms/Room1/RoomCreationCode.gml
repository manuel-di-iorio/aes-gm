// STRING:
var encryptedStr = aes_encrypt_string("Hello world", "Password sicura12345@") // Output codificato in base64
var decryptedStr = aes_decrypt_string(encryptedStr, "Password sicura12345@")
show_debug_message(decryptedStr) // Hello world

// BUFFER:
var buf = buffer_create(12, buffer_fixed, 1);
buffer_write(buf, buffer_text, "Hello world!");
var encryptedBuffer = aes_encrypt(buf, "miaPassword");
var decryptedBuffer = aes_decrypt(encryptedBuffer, "miaPassword");
show_debug_message(buffer_read(decryptedBuffer, buffer_text))