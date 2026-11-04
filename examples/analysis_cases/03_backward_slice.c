void copy_with_derived_size(char *dst, const char *src, unsigned long len) {
    unsigned long copy_size = len;
    memcpy(dst, src, copy_size);
}
