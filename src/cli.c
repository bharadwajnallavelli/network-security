/*
 ============================================================================
 Name        : Network.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "cli.h"
#include "ca.h"
#include "authorization.h"

bool done = false;
int exitHandler(char *input);

int exitHandler(char *input)
{
	printf("Exiting\n");
	done = true;
	return 0;
}

int function1(char *input)
{
	printf("Command1 - Input: %s\n", input);
	return 0;
}

int function2(char *input)
{
	printf("Command2 - Input: %s\n", input);
	return 0;
}

int cmd_initialize_authorization(char *input)
{
	EVP_PKEY *p_public_key;

	printf("Initialize Authorization\n");
	return 0;
}


void cli() {
	char input[128];
	char *p_cmd;

	uint i;

	InputHandler handlers[] = {
			{.command="cmd1", .handler=&function1},
			{.command="cmd2", .handler=&function2},
			{.command="init", .handler=&cmd_initialize_authorization},
			{.command="exit", .handler=&exitHandler},
			{.command="last", .handler=NULL}
	};

	while(!done){
		printf("> ");
		fgets(input, 128, stdin);

		p_cmd = strtok(input, " \n");
		if(p_cmd == NULL)
			continue;

		i = 0;
		while(1) {
			if(strcmp(handlers[i].command, "last") == 0) {
				printf ("Invalid Command\n");
				break;
			}
			else if(strcmp(handlers[i].command, p_cmd) == 0) {
				// Execute the command
				handlers[i].handler(input);
				break;
			}
			i++;
		}
	}

}



