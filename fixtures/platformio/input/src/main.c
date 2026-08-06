/* Broken on purpose. The upload gate runs pio check (cppcheck) against this file
 * and expects defects at all three severity levels. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int helper_never_called(int x) {
    return x * 2;
}

int read_uninitialized(void) {
    int value;
    return value; /* uninitvar: high */
}

void null_dereference(void) {
    char *p = NULL;
    *p = 'x'; /* nullPointer: high */
}

void buffer_overrun(void) {
    char buf[4];
    strcpy(buf, "too long for four bytes"); /* bufferAccessOutOfBounds */
}

int main(void) {
    char name[16];
    scanf("%s", name); /* invalidscanf: medium */
    int leaked = *(int *)malloc(sizeof(int)); /* leak + uninit read */
    (void)leaked;
    return 0;
}
