int conditional_command(const char *command, int enabled) {
    if (enabled) {
        system(command);
        return 1;
    }
    return 0;
}
