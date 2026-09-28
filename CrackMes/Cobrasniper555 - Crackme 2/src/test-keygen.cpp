//////////////////////////////////////////
// Crackme : cobrasniper555's Crackme #2
// reversed by : Nuno_1
// Skills : 2 (from a scale of 1 to 10)
// Used applications : ollydbg
//////////////////////////////////////////

#include "stdio.h"
#include "stdlib.h"
#include "math.h"
#include "string.h"

char *getSerial(const char *name, char *newSerial)
{
    unsigned int sum = 0;
    unsigned int sum2= 0;

    unsigned int char1;
    unsigned int char2;
    for ( int i=0;i<strlen(name);i++ )
    {
        char1 = name[i];
        if ( i == 0 )
        {
            char2 =  name[i] + 5;
            char1 = char2;
            
        }
        else
        {
            char1 += name[i-1];
        }


        char1 = char1 ^ 0x12c;
        char1 += (char1 << 2);
        char1 <<= 2;
        
        sum = (char1 >> 2) & 0xF0F0F0F0;
    
    }

    for ( int i=strlen(name);i>0;i-- )
    {
        char1 = name[i];
        if ( i == strlen(name) )
        {
            char2 =  name[i] + 5;
            char1 = char2;

        }
        else
        {
            char1 += name[i+1];
        }


        char1 = char1 ^ 0x12c;
        char1 += (char1 << 2);
        char1 <<= 2;

        sum2 = (char1 >> 2) & 0xF0F0F0F0;

    }
    sprintf(newSerial,"REG-%lX-%lX-KEY",sum,(sum+sum2));
    return newSerial;
}
int main(int argc,char *argv[])
{
    unsigned int finalResult = 0;
    char nameStr[1024];
    char serial[1024];

    printf("Please enter the name of to generate a key for :");

    scanf("%s",&nameStr);

    getSerial( nameStr,serial );
    printf ("The Serial is %s\n",serial);
    return 0;
}