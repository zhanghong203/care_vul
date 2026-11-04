void double_release(void) {
    char *buffer = malloc(64);
    if (buffer == 0) {
        return;
    }
    free(buffer);
    free(buffer);
}
