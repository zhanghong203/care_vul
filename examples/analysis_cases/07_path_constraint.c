void early_return_copy(const char *src, unsigned long len) {
    char dst[16];
    if (len > sizeof(dst)) {
        return;
    }
    memcpy(dst, src, len);
}
