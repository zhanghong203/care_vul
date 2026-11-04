void release_buffer(void) {
    char *buffer = malloc(64);
    if (buffer == 0) {
        return;
    }
    free(buffer);
}
