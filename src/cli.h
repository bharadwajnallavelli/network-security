/*
 * cli.h
 *
 *  Created on: Mar 19, 2017
 *      Author: bill
 */

#ifndef CLI_H_
#define CLI_H_

typedef struct InputHandler {
	char command[32];
	int (*handler)(char *input);
}InputHandler;

void cli();

#endif /* CLI_H_ */
