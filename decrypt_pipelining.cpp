/*********************************************
UNIVERSIDAD DEL VALLE DE GUATEMALA
CC3056 - Programación de Microprocesadores
Ciclo 2 - 2019

Autores: Gustavo Mendez y Roberto Figueroa
Fecha: 10/09/2019
Archivo: decrypt_pipelining.cpp
Descripcion: PROYECTO 3 - Desencripcion DES hecho con 4 rondas, 
        tamanio de bloque de 8 y el archivo compilado 
        es usado como comando de linea en la CLI de 
        la RPI.

---------------------USO-----------------------
USO: $ ./modulo archivoEncriptado

--------------------TODOS----------------------
- Implementacion de variables condicionales
- Establecimiento de las 3 fases de pipelining,
        conforme la encriptacion demanda.

**********************************************/
#include <time.h>
#include <sstream>
#include <fstream>
#include <codecvt>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

using namespace std;

//Definiciones del algoritmo DES de desencripcion
#define ROUNDS 4                
#define BLOCK_CAPACITY 8        //Bytes
#define THREADS 3               

//Declaracion de estructura para pasar parametros entre pthreads
struct data_decrypt {
        // Declaracion de contenido encriptado
	uint32_t leftSide;
	uint32_t rightSide;
	uint32_t round;

	//Declaracion de llaves
        uint32_t KEYS[ROUNDS] = {
                0xFF91B5F5,
                0xF9281A0E,
                0x84282A36,
                0xE8D63C4A
        };

} ;

// Pthreads y variables condicionales
pthread_mutex_t decrypt_lock;
pthread_cond_t decrypt_threshold_cv;



/*********************************************
Funcion XOR para la operacion de la misma entre 
el bloque de bits, con la llave designada 

@params: block (32 bits), key (32 bits)
@return: entero de 32 bits
*********************************************/
uint32_t XOR_function(uint32_t block, uint32_t key)
{
    return block ^ key;
}

/*********************************************
Funcion de desencripcion por bloque, realizando 
toda la logica de DES

@params: leftSide (32 bits), rightSide (32 bits), 
        rounds (int 32 bits), keys (array 32 bits)
@return: entero de 64 bits
*********************************************/
uint64_t decrypt(uint32_t leftSide, uint32_t rightSide, uint32_t rounds, uint32_t keys[])
{
        uint32_t leftSideTemp, rightSideTemp;

        for (int i = 0; i < rounds; i++)
        {       
                // El lado izquierdo temporal sera igual a (lado izquierdo XOR llave) XOR derecha
                leftSideTemp = XOR_function(leftSide, keys[rounds - i - 1]) ^ rightSide;
                // La parte derecha temporal viene a ser el lado izquierdo
                rightSideTemp = leftSide;

                //Si no estamos en la ultima iteracion, se realiza asignacion en pares (left-left, right-right)
                if(i != (rounds - 1)) {
                    leftSide = leftSideTemp;
                    rightSide = rightSideTemp;
                }
                else // Cuando ocurre la ultima iteracion, la asignacion es en pares cruzados (left-right, right-left)
                {
                        leftSide = rightSideTemp;
                        rightSide = leftSideTemp;
                }
        }
        // Corrimiento a la izquierda de 32 bits para luego realizar un OR de la parte izquirda con la derecha
        return (uint64_t) leftSide << 32 | rightSide;
}

/*********************************************
Funcion realizada por los pthreads para desencriptar

@params: currentData (puntero)
@return: void
*********************************************/

void* decryptThread(void *currentData)
{

	pthread_mutex_lock(&decrypt_lock);
	struct data_decrypt *threadData = (struct data_decrypt *)currentData;
	pthread_mutex_unlock(&decrypt_lock);
	pthread_exit((void *) (uintptr_t) decrypt(threadData->leftSide, threadData->rightSide, threadData->round, threadData->KEYS));

}



/*********************************************
Funcion de desencripcion por bloque, realizando 
toda la logica de DES

@params: cryptedFile (archivo), decryptedFile (archivo), 
        rounds (int 32 bits), keys (array 32 bits)
@return: entero de 64 bits
*********************************************/
void decrypt_file(FILE *cryptedFile, FILE *decryptedFile, uint32_t rounds, uint32_t keys[])
{       
        // Declaracion de estructura
        data_decrypt decryptDataParams;
        uint64_t prevBlock = 0xF0CCFACE;
        //Declaracion de variables iniciales
	void * returnData;        
	size_t result;
	uint64_t currentBlock;
	int rc;

        cout << ">>> Desencriptando...";
        // Mientas el archivo contenga texto, se leera
        while (!feof(cryptedFile))   
        {
                //cout << ". ";
                // Leer 8 bytes del archivo ingresado.
                result = fread(&currBlock, 1, BLOCK_CAPACITY, cryptedFile);
                // XOR bit a bit con bloque anterior
                currentBlock ^= prevBlock;
                // Corrimiento de 32 bits y realizacion de un AND para hallar el lado izquierdo 
                decryptDataParams.leftSide = (currBlock >> 32) & 0xFFFFFFFF;
                // Realizacion de un AND para hallar el lado derecho
                decryptDataParams.rightSide = currBlock & 0xFFFFFFFF;
                decryptDataParams.round = rounds;
                
        }

        //Implementacion de threads
        pthread_t threads[THREADS];

        if (pthread_mutex_init(&decrypt_lock, NULL) != 0)
        {
                printf("\nInicio de mutex fallido\n");
        }

        for (int i = 0; i < THREADS; i++)
        {
                rc = pthread_create(&threads[i], NULL, decryptThread, (void *)&decryptDataParams);

                if (rc)
                {
                        printf("\nNo se ha podido crear thread :[%s]", rc);
                        exit(-1);
                }
        }

        for (int i = 0; i <= THREADS; i++)
        {
                pthread_join(threads[i], &returnData);
                currentBlock = *(uint64_t *)returnData;
                // Escritura del bloque de regreso en el archivo desencriptado
                fwrite(&currBlock, 1, BLOCK_CAPACITY, decryptedFile);
        }

        pthread_mutex_destroy(&decrypt_lock);
        pthread_exit(NULL);
        cout << endl;
}


/************************************
*
*                MAIN
*
************************************/
int main(int argc, char *argv[])
{
        // Declaracion de archivos
        FILE *cryptedFile, *decryptedFile;
        size_t result;

        uint32_t KEYS[ROUNDS] = {
		0xFF91B5F5,
		0xF9281A0E,
		0x84282A36,
		0xE8D63C4A
	};

        // Verificar si los parametros pasados son correctos
        if (argc != 2)
        {
                fprintf(stderr, "Formato incorrecto, intenta de nuevo!\n");
                fprintf(stderr, "$ ./modulo archivoEncriptado\n");
                return EXIT_FAILURE;
        }

        // Abriendo archivo pasado como parametro, en formato de lectura
        cryptedFile = fopen(argv[1], "r");
        //Si ocurre un error al abrir archivo a desencriptar
        if (!cryptedFile)
        {
                printf("Error al abrir el archivo: ");
                cout << argv[1] << endl;
                return EXIT_FAILURE;
        }
        
        cout << "Abriendo archivo encriptado " << argv[1] << ", detectado correctamente" << endl;
        //Abriendo archivo para escribir mensaje desencriptado en el mismo
        decryptedFile = fopen("decryptedFile.txt", "w");
        
        // Declaracion del tiempo cuando comienza el programa
        clock_t tStart = clock();
        decrypt_file(cryptedFile, decryptedFile, ROUNDS, KEYS);
        //Estableciendo lapso de tiempo empleado al desencriptar
        printf("[!] Tiempo empleado: %.3fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

        cout << ">>> El archivo ha sido desencriptado, archivo: decryptedFile.txt!" << endl;

        //Cierre seguro de archivos usados
        fclose(cryptedFile);
        fclose(decryptedFile);

        return 0;
}
