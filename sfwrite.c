#include "common.h"
#include "sfwrite.h"

/**
* Uses a mutex to lock an output stream so it is not interleaved when
* printed to by different threads.
* @param lock Mutex used to lock output stream.
* @param stream Output stream to write to.
* @param fmt format string used for varargs.
*/
void sfwrite(pthread_mutex_t lock, FILE* stream, char *fmt, ...){
	pthread_mutex_lock(&lock);
	va_list t;
	va_start(t,fmt);
	vfprintf(stream,fmt,t);
	va_end(t);
	pthread_mutex_unlock(&lock);
}


void Read_Audit(FILE *stream){
   fflush(stream);
   fseek(stream,0,SEEK_SET);
    char filebuf[80];
    while(fgets(filebuf,80,stream)){
      printf("%s",filebuf);
    }

}



