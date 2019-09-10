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

using namespace std;

//Definiciones del algoritmo DES de desencripcion
#define ROUNDS 4
#define BLOCK_CAPACITY 8

//Declaracion de llaves
uint32_t KEYS[ROUNDS] = {
    0xFF91B5F5,
    0xF9281A0E,
    0x84282A36,
    0xE8D63C4A,
    0x0C402C6F,
    0x2296CB30,
    0x9FF9D76E,
    0x243A5572,
    0xA4AE9DD0,
    0x999F201E,
    0x9A0CB9A5,
    0x349968F5,
    0x62FD58D0,
    0x339DFC3C,
    0x4815AD1E,
    0x7312DEAD
};

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
Funcion de desencripcion por bloque, realizando 
toda la logica de DES

@params: cryptedFile (archivo), decryptedFile (archivo), 
        rounds (int 32 bits), keys (array 32 bits)
@return: entero de 64 bits
*********************************************/
void decrypt_file(FILE *cryptedFile, FILE *decryptedFile, uint32_t rounds, uint32_t keys[])
{       
        bool isFirstTime = true;
        uint32_t leftSide, rightSide;
        size_t resultado;
        uint64_t currBlock, prevBlock, saved;
        cout << ">>> Desencriptando...";
        // Mientas el archivo contenga texto, se leera
        while (!feof(cryptedFile))   
        {
                cout << ". ";
                resultado = fread(&currBlock, 1, BLOCK_CAPACITY, cryptedFile);
                saved = currBlock;
                // Corrimiento de 32 bits y realizacion de un AND para hallar el lado izquierdo 
                leftSide = (currBlock >> 32) & 0xFFFFFFFF;
                // Realizacion de un AND para hallar el lado derecho
                rightSide = currBlock & 0xFFFFFFFF;
                // Se desencripta la linea actual, segun el lado der. e izq. pasados como parametro
                currBlock = decrypt(leftSide, rightSide, ROUNDS, keys);
                // Como no hay bloque previo en el primer intento, se realiza un if
                if (isFirstTime)
                {
                        currBlock ^= 0xF0CCFACE;
                        isFirstTime = false;
                }
                else
                {
                        currBlock ^= prevBlock;
                }
                //Asignacion, bloque anterior como el bloque salvado anteriormente
                prevBlock = saved;
                // Escritura del bloque de regreso en el archivo desencriptado
                fwrite(&currBlock, 1, BLOCK_CAPACITY, decryptedFile);
        }
        cout << endl;
}

/*********************************************
Funcion de desencripcion por bloque, realizando 
toda la logica de DES

@params: start (time), end (time), 
        diff (time)
@return: int
*********************************************/
int calculate_diff_time(timespec start, timespec end, timespec &diff)
{

        if ((end.tv_nsec - start.tv_nsec) < 0)
        {
                calculate_diff_time.tv_sec = end.tv_sec - start.tv_sec - 1;
                calculate_diff_time.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
        }
        else
        {
                calculate_diff_time.tv_sec = end.tv_sec - start.tv_sec;
                calculate_diff_time.tv_nsec = end.tv_nsec - start.tv_nsec;
        }
        return 0;
}

/************************************
*
*                MAIN
*
************************************/
int main(int argc, char *argv[])
{
        // Estructuras que contiene un intervalo dividido en segundos y nanosegundos
        timespec t1, t2, diff_t;
        // Declaracion de archivos
        FILE *cryptedFile, *decryptedFile;

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
        decryptedFile = fopen("decryptedFile.txt", "w");
        
        // Calculando el tiempo del programa
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);
        decrypt_file(cryptedFile, decryptedFile, ROUNDS, KEYS);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2);

        //Estableciendo lapso de tiempo empleado al desencriptar
        calculate_diff_time(t1, t2, diff_t);

        // Prints del tiempo empleado, 
        int sec = diff_t.tv_sec;
        int ns = diff_t.tv_nsec;

        printf("[!] Tiempo empleado: \t%d.%d\n", sec, ns);
        cout << ">>> El archivo ha sido desencriptado, archivo: decryptedFile.txt!" << endl;

        //Cierre seguro de archivos usados
        fclose(cryptedFile);
        fclose(decryptedFile);

        return 0;
}
