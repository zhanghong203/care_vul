void bounded_copy(const char *src, unsigned long len) {
    char dst[16];
    if (len <= sizeof(dst)) {
        memcpy(dst, src, len);
    }
}
