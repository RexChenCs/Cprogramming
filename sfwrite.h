#include <stdarg.h>
#include <sys/file.h>


/**
* Uses a mutex to lock an output stream so it is not interleaved when
* printed to by different threads.
* @param lock Mutex used to lock output stream.
* @param stream Output stream to write to.
* @param fmt format string used for varargs.
*/
void sfwrite(pthread_mutex_t lock, FILE* stream, char *fmt, ...);
void Read_Audit(FILE *stream);


