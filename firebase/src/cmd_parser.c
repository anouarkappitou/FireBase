#include "cmd_parser.h"


// this should be refactored

static char* _arg_value( char* cmd,
                                char* delim ,
                                char* arg )
{

        char* dup = strdup( cmd );

        char* key = strtok( dup , delim );
        char* value = strtok( NULL , delim );

        while( key != NULL && value != NULL )
        {
                key++;
                if( strcmp( key , arg ) == 0 )
                {
                        return value;
                }

                key = strtok( NULL , delim );
                value = strtok( NULL , delim );
        }

        return NULL;
}

char* _get_action( char* cmd , char* action )
{
        char* walker = cmd;

        for(; *walker != ' ' && *walker != '\0' ; walker++ , action++ )
        {
                *action = *walker;
        }

        *action = '\0';

        return walker;
}

int parse_cmd( char* cmd , cmd_t* rule )
{
        ASSERT( cmd );
        ASSERT( rule );

        char* action = ( char* ) ALLOC( sizeof( char ) * 10 );

        cmd = _get_action( cmd , action );

        // ALLOW -saddr 127.0.0.1 -sport 80

        if( strcmp( action , "ADD" ) == 0 )
        {
                printk( "adding" );
                rule->op = ADD;

        }else if( strcmp( action , "DELETE" ) == 0 )
        {
                rule->op = DELETE;

        }else if( strcmp( action , "MODIFY" ) == 0 ){

                rule->op = MODIFY;

        }else
        {
                // command error
                printk( "Error parsing command : %s" , cmd );

                return -1;
        }

             char* val = _arg_value( cmd , " " , "op" );

        if( strcmp( val , "ALLOW" ) == 0 )
        {

                rule->action = ALLOW;

        }else if( strcmp( val , "DENY" ) == 0 )
        {
                rule->action = DENY;
        }else
        {
                // command error
                printk( "Error parsing action: %s" , val );

                return -1;
        }

        // we know that the first token is an action

        val = _arg_value( cmd , " " , "srcp" );

        if( val  != NULL )
        {
                rule->sport = port_to_bytes( _arg_value( cmd , " " ,  "srcp" ) );
        }else
        {
                rule->sport = EMPTY;
        }


        if(  val != NULL )
        {
                rule->saddr = val;
        }else
        {
                rule->saddr = NULL;
        }

        val = _arg_value( cmd , " " , "daddr" );

        if( val != NULL )
        {
                rule->daddr = val;
        }else
        {
                rule->daddr = NULL;
        }

               val = _arg_value( cmd , " " , "smask" );

        if( val != NULL )
        {
                rule->smsk = val;
        }else
        {
                rule->smsk = NULL;
        }

        val = _arg_value( cmd , " " , "dmask" );

        if( val != NULL )
        {
                rule->dmsk = val;
        }else
        {
                rule->dmsk = NULL;
        }

        rule->type = INPUT;

        val = _arg_value( cmd , " " , "out" );

        if( val != NULL )
        {
                rule->type = OUTPUT;
        }

        rule->proto = ALL;

        val = _arg_value( cmd , " " , "proto" );

        if( val != NULL )
        {
                if( strcmp( val , "TCP" ) == 0 )
                {
                        rule->proto = TCP;
                }

                if( strcmp( val , "UDP" ) == 0 )
                {
                        rule->proto = UDP;
                }

                if( strcmp( val , "ICMP" ) == 0 )
                {
                        rule->proto = ICMP;
                }

                if( strcmp( val , "IGMP" ) == 0 )
                {
                        rule->proto = IGMP;
                }
        }

        val = _arg_value( cmd , " " , "state" );

        rule->enabled = -1;

        if( val != NULL )
        {
                if( strcmp( val , "ENABLE" ) == 0 )
                {
                        rule->enabled = 1;
                }else
                {
                        rule->enabled = 0;
                }
        }

        switch( rule->op )
        {
                case ADD:
                {
                        printk( "\nADD " );
                }break;
                case DELETE:
                {
                        printk( "\nDELETE " );
                }break;
                case MODIFY:
                {
                        printk( "\nMODIFY " );
                }break;
        }

        switch( rule->action )
        {
                case ALLOW:
                        printk( "ALLOWING " );
                        break;

                case DENY:
                              case DENY:
                        printk( "DENIYING " );
                        break;
        }

        printk( "source addr : %s , destination addr : %s , source port : %d , destination port : %d , source mask : %s , destination mask : %s" ,
                rule->saddr ,       rule->daddr ,          rule->sport ,       rule->dport ,           rule->smsk       , rule->dmsk               );

        if( rule->type == INPUT )
        {
                printk( "type : INPUT\n" );
        }else
        {
                printk( "type : OUTPUT\n" );
        }

        return 0;

}


int rule_init( firebase_t* app , cmd_t *cmd , rule_t* rule )
{
        NULL_CHECK( cmd );
        NULL_CHECK( app );
        NULL_CHECK( rule );

        if( !(cmd->enabled < 0) )
        {
                if( cmd->enabled )
                {
                        app->state = ENABLED;
                }else
                {
                        app->state = DESABLED;
                }
        }

        rule->saddr     = ip_to_bytes( cmd->saddr );
        rule->daddr     = ip_to_bytes( cmd->daddr );
        rule->smsk      = ip_to_bytes( cmd->smsk );
        rule->dmsk      = ip_to_bytes( cmd->dmsk );

        rule->type      = cmd->type;
        rule->proto     = cmd->proto;
        rule->sport     = cmd->sport;
        rule->dport     = cmd->dport;
        rule->if_name   = cmd->if_name;

        return 0;

}

#endif


