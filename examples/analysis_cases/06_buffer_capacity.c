void fixed_buffer_copy(const char *src, unsigned long len) {
    char dst[32];
    memcpy(dst, src, len);
}
