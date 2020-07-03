#include <stdlib.h>
#include <time.h>
#include "gui.h"
#include "ccrypt.h"

int main(int argc, char **argv) {
    int status;
    status = init_gui(argc, argv);
    return status;
}
