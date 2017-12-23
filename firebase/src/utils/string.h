#ifndef STRING_UTILS_H
#define STRING_UTILS_H

#ifndef __KERNEL
        #include <string.h>
        #include <stdlib.h>
#else
        #include <linux/string.h>
#endif



#define NULL_CHECK( obj ) obj == NULL || obj == 0 ? 1 : 0
#define ARY_SIZE( array ) sizeof( array ) / sizeof( array[0] )
#define INVALID 0

// macros used to define allocation function

#define ALLOC( size ) if( __KERNEL ) kmalloc( size , GFP_KERNEL ); else malloc( size );
#define REALLOC( p , size ) krealloc( p , size , GFP_KERNEL )

unsigned int ip_to_bytes( char* str_ip  )
{

        if( str_ip == NULL ) return 0;

        unsigned int ip = 0;
        int i = 0;
        char* c = str_ip;

        printk( "\nconverting ip to bytes : %s\n" , str_ip );

        for( i = 0;i < 4 ; ++i )
        {

        int byte = 0;

        for(; *c != '.' && *c != '\0' ; ++c )
        {

            if( *c >= '0' && *c <= '9' )
            {
                byte *= 10;
                byte += *c - '0';
            }
        }

        ++c;

        if( byte > 256 )
            return INVALID;

        printk( "\nip : %d , bytes : %d \n"  , ip , byte );

        ip *= 256;
        ip += byte;
        }

        return ip;
}


unsigned int port_to_bytes( char* str_port )
{
        unsigned int port = 0;
        char* it = str_port;

        while( *it != '\0' )
        {
                port *= 10;
                port += *it - '0';
                it++;
        }

        return port;
}

size_t num_of( const char* str , char occurence )
{
        char* walker = str;

        size_t num = 0;

        while( *str != '\0' )
        {
                if( *str == occurence )
                        num++;

                str++;
        }

        return num;
}

char * strdup(const char *str)
{
        size_t siz;
        size_t rsiz;
        char   *result;

        if (str == NULL) {
                return NULL;
        }

        siz = strlen(str) + 1;
        result = (char *)ALLOC(siz);

        rsiz = strlcpy(result, str, siz);

        return result;
}


char * strtok(char * str, char *comp)
{
        static int pos;
        static char *s;
        int i =0, start = pos;

        // Copying the string for further calls of strtok
        if(str!=NULL)
                s = str;

        i = 0;
        int j = 0;
        //While not end of string
        while(s[pos] != '\0')
        {
                j = 0;
                //Comparing of one of the delimiter matches the character in the string
                while(comp[j] != '\0')
                {
                        //Pos point to the next location in the string that we have to read
                        if(s[pos] == comp[j])
                        {
                                //Replace the delimter by \0 to break the string
                                s[pos] = '\0';
                                pos = pos+1;
                                //Checking for the case where there is no relevant string before the delimeter.
                                //start specifies the location from where we have to start reading the next character
                                if(s[start] != '\0')
                                        return (&s[start]);
                                else
                                {
                                        // Move to the next string after the delimiter
                                        start = pos;
                                        // Decrementing as it will be incremented at the end of the while loop
                                        pos--;
                                        break;
                                }
                        }
                        j++;
                }
                pos++;
        }//End of Outer while

        pos = 0;
        s[pos] = '\0';
        if(s[start] == '\0')
                return NULL;
        else
                return &s[start];
}



#endif


