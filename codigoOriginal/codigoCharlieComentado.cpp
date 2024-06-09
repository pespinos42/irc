#include <iostream>
/*
- Propósito: Proporciona las funcionalidades básicas de entrada y salida en C++.
- Uso: Se utiliza para imprimir mensajes en la consola, como logs y mensajes de error, usando std::cout y std::cerr.
*/
#include <string>
/*
- Propósito: Proporciona la clase std::string, que es una forma segura y cómoda de manipular cadenas de caracteres en C++.
- Uso: Para manejar los datos de texto como mensajes de IRC, nombres de usuario, contraseñas, etc.
*/
#include <vector>
/*
- Propósito: Proporciona la clase std::vector, que es una secuencia dinámica que puede cambiar de tamaño.
- Uso: Para almacenar colecciones de datos como una lista de clientes conectados o una lista de descriptores de archivos para poll().
*/
#include <map>
/*
- Propósito: Proporciona la clase std::map, que es un contenedor asociativo que almacena pares clave-valor ordenados.
- Uso: Para gestionar asociaciones como la relación entre canales y usuarios o entre nombres de usuario y sockets.
*/
#include <set>
/*
- Propósito: Proporciona la clase std::set, que es un contenedor que almacena elementos únicos en orden específico.
- Uso: Para gestionar colecciones de elementos únicos, como una lista de usuarios en un canal sin duplicados.
*/
#include <sys/socket.h>
/*
- Propósito: Proporciona definiciones para estructuras y funciones necesarias para el uso de sockets.
- Uso: Para crear y manipular sockets con funciones como socket(), bind(), listen(), accept(), recv(), send(), etc.
*/
#include <netinet/in.h>
/*
- Propósito: Define constantes y estructuras necesarias para la programación de sockets de dominio de Internet.
- Uso: Para la configuración de direcciones y puertos en la estructura sockaddr_in.
*/
#include <arpa/inet.h>
/*
- Propósito: Proporciona funciones para conversiones de direcciones de red.
- Uso: Para convertir direcciones IP entre formatos binarios y de texto con funciones como inet_pton() y inet_ntop().
*/
#include <unistd.h>
/*
- Propósito: Proporciona acceso a la API de POSIX, incluyendo funciones para la gestión de descriptores de archivos.
- Uso: Para operaciones básicas del sistema como close(), read(), write(), y usleep().
*/
#include <poll.h>
/*
- Propósito: Proporciona la interfaz para la función poll(), que es utilizada para la multiplexación de entradas y salidas.
- Uso: Para monitorear múltiples descriptores de archivos y detectar eventos como la disponibilidad de datos para leer o la capacidad para escribir.
*/
#include <cstring>
/*
- Propósito: Proporciona funciones para manipular cadenas de caracteres en estilo C.
- Uso: Para funciones como strcpy(), strlen(), strcmp(), y memset(), que son útiles para trabajar con datos en formato de cadena de caracteres.
*/
#include <fcntl.h>
/*
- Propósito: Proporciona operaciones de control de archivos.
- Uso: Para configurar descriptores de archivos, por ejemplo, estableciendo el modo no bloqueante con fcntl().
*/
#include <algorithm>
/*
- Propósito: Proporciona una colección de algoritmos que operan sobre contenedores.
- Uso: Para operaciones comunes de manipulación de datos como std::find(), std::remove_if(), y std::for_each().
*/

const int MAX_CLIENTS = 100;
//define el numero máximo de clientes que el servidor puede manejar simultáneamente
const int BUFFER_SIZE = 1024;
//define el tamaño del búfer utilizado para leer y escribir datos a través de las conexiones de red

class IRCServer {
public:
    IRCServer(int port, const std::string& password)
        : port(port), password(password), server_socket(-1) {}
//configura los valores iniciales necesarios para que el servidor IRC funcione
//inicializa el server_socket a -1 para indicar que aún no se ha establecido ningún socket

    bool start() {
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
//esta línea crea un socket de servidor
//AF_INET -> indica que el dominio del socket es IPv4
//SOCK_STREAM -> indica que se está solicitando un socket de flujo. Los sockets de flujo proporcionan una conexion bidireccional confiable, con un flujo continuo de bytes. Este tipo de socket se utiliza comúnmente con el protocolo TCP
//0 -> generalmente se deja en 0, lo que le dice a la función que utilice el protocolo predeterminado para el tipo de socket especificado (en este caso TCP para SOCK_STREAM)
//server_socket -> es una variable que almacenará el descriptor del socket devuelto por la función socket(). Si la creación del socket falla devolverá -1
        if (server_socket == -1) {
            perror("socket");
            return false;
        }

        // Configurar el socket como no bloqueante
        int flags = fcntl(server_socket, F_GETFL, 0);
//fcntl -> función utilizada para manipular descriptores de archivo
//server_socket -> es el descriptor del archivo del socket de servidor que fue creado anteriormente
//F_GETFL -> es una operación que le indica a fcntl que debe obtener las banderas de estado del descriptor de archivo
//0 -> este tercer parámetro se usa con ciertas operaciones fcntl pero no es necesario para F_GETFL, así que se pasa como 0. Se ignora en este caso
//flags -> el valor devuelto por fcntl con F_GETFL es un conjunto de banderas (flags) que representan el estado del descriptor de archivo
        if (flags == -1 || fcntl(server_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
            perror("fcntl");
            close(server_socket);
            return false;
        }
//flags == -1 -> comprueba si hubo un error al obtener las banderas de estado del descriptor de archivo en la línea anterior. Si fcntl devolvió -1 indica que hubo un error
//fcntl(server_socket, F_SETFL, flags | O_NONBLOCK) == -1
//esta parte de la condición intenta establecer las banderas de estado del descriptor de archivo para incluir O_NONBLOCK (modo no bloqueante)
//F_SETFL -> comando que le indica a fcntl que debe establecer las banderas de estado
//flags | O_NONBLOCK -> usa una operación OR a nivel de bits para agregar la bandera O_NONBLOCK a las banderas actuales (flags). Esto garantiza que el socket opere en modo no bloqueante

        sockaddr_in server_addr;
//se declara server_addr de tipo struct sockaddr_in. Esta estructura se utiliza para especificar una dirección IP y un número de puerto en las operaciones de red, especialmente cuando se trabaja con sockets en la familia de direcciones IPv4 (AF_INET). La estructura sockaddr_in tiene el siguiente contenido:
/*
struct sockaddr_in {
    short int          sin_family;   // Familia de direcciones (siempre AF_INET para IPv4)
    unsigned short int sin_port;     // Número de puerto (debe estar en orden de red)
    struct in_addr     sin_addr;     // Dirección IP (estructura in_addr)
    char               sin_zero[8];  // Relleno para alinear con la estructura sockaddr
};
sin_port -> se utiliza la función htons (host to network short) para convertir un número de puerto del orden de bytes del host al orden de bytes de red
sin_addr -> es una estructura in_addr que contiene la dirección IP. La estructura in_addr típicamente tiene un solo campo s_addr que es la dirección IP en orden de red
sin_zero -> es un array de 8 bytes que se utiliza para alinear la estructura sockaddr_in con la estructura genérica socaddr. No se utiliza para almacenar información de la dirección y generalmente se inicializa a ceros
*/
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
//esta línea indica al socket que escuche en todas las interfaces de red disponibles de la máquina. Esto significa que el servidor estará disponible para recibir conexiones en cualquier dirección IP asociada con la máquina, ya sea IPv4 o IPv6. En el contexto de un servidor de red este enfoque es útil cuando se desea que el servidor escuche en todas las interfaces de red de la máquina. Por ejemplo, si un servidor tiene múltiples interfaces de red (como una interfaz Ethernet y una interfaz Wi-Fi), establecer la dirección IP en INADDR_ANY permite al servidor aceptar conexiones entrantes en cualquiera de estas interfaces sin tener que especificar una dirección IP específica
//INADDR_ANY -> es una constante predefinida que representa la dirección IP "cualquiera" o "todas las interfaces". Tiene el valor especial de 0.0.0.0
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
            perror("bind");
            close(server_socket);
            return false;
        }
//estas líneas están relacionadas con la vinculación (binding) del socket del servidor a una dirección IP y un número de puerto específicos
//bind -> es una función de la API de sockets que asocia un socket con una dirección IP y un número de puerto específicos. Toma los siguientes tres argumentos:
//server_socket -> es el descriptor de socket del servidor que se va a vincular
//(struct sockaddr*)&server_addr -> es un puntero al struct sockaddr que contiene la dirección y el puerto del servidor. Debido a la necesidad de compatibilidad con la función bind, se realiza un casting explícito del puntero a struct sockaddr*
//sizeof(server_addr) -> es el tamaño en bytes del struct server_addr
//si la vinculación es exitosa, bind devuelve 0, si hay un error devuelve -1

        if (listen(server_socket, MAX_CLIENTS) == -1) {
            perror("listen");
            close(server_socket);
            return false;
        }
//estas líneas están relacionadas con la transición del socket del servidor al estado de escucha (listening state), lo que permite al servidor aceptar conexiones entrantes
//listen -> es una función de la API de sockets que coloca un socket en el estado de escucha, lo que significa que el socket está esperando conexiones entrantes. Toma los siguientes dos argumentos:
//server_socket -> es el descriptor de socket del servidor que se pondrá en escucha
//MAX_CLIENTS -> el segundo argumento es el tamaño de la cola de conexiones pendientes. Indica cuántas conexiones pueden estar esperando ser aceptadas mientras el servidor está ocupado manejando otras conexiones
//si la operación de escucha es exitosa listen devuelve 0, si hay algún error -1

        struct pollfd pfd;
//struct pollfd -> es una estructura definida en la biblioteca de C <poll.h>. Esta estructura se utiliza para especificar un descriptor de archivo para ser monitoreado por la función poll(). Contiene los siguientes campos:
        pfd.fd = server_socket;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pollfds.push_back(pfd);
//fd -> es el descriptor de archivo que se va a monitorear
//events -> especifica los eventos que el programa está interesado en monitorear en el descriptor de archivo especificado. POLLIN es una máscara de bits que incica que se deben monitorear eventos de lectura (es decir, eventos que indican que hay datos disponibles para leer en el socket). Esto significa que pfd estará interesado en saber si hay datos listos para ser leídos desde el socket del servidor
//revents -> almacena los eventos que realmente ocurrieron en el descriptor de archivo después de que poll() regrese. Se establece inicialmente en cero. Al establecerlo en cero, se está asegurando de que esté limpio antes de que se realice el monitoreo
//pollfds.push_back(pdf) -> pollfds es un vector que almacena estructuras pollfd para monitorear varios descriptores de archivo. Aquí, la estructura pfd, que ha sido configurada para monitorear eventos en el socket del servidor, se agrega al final del vector pollfds. Esto significa que pollfds ahora incluye la información necesaria para monitorear eventos en el socket del servidor


        std::cout << "Server started on port " << port << std::endl;
        return true;
    }

    void run() {
        while (true) {
            int poll_count = poll(pollfds.data(), pollfds.size(), -1);
//esta línea usa la función poll() para monitorear múltiples descriptores de archivo y esperar eventos en ellos
//poll_count -> almacenará el resultado de la llamada a poll()
//poll -> es una función de la biblioteca estándar de C (declarada en <poll.h> que espera eventos en uno o más descriptores de archivo
//pollfds.data() -> devuelve un puntero al perimer elemento del vector pollfds. Esto es necesario porque poll() espera un puntero a una matriz de estructuras pollfd
//pollfds.size() -> devuelve el número de elementos en el vector pollfds. Esto es necesario porque poll() necesita saber cuántos descriptores de archivo están siendo monitoreados
//-1 -> el tercer argumento de poll() es un tiempo de espera en milisegundos. -1 indica que poll() debe esperar indefinidamente hasta que ocurra un evento en alguno de los descriptores de archivo
//FUNCIONAMIENTO DE POLL
//poll() examina múltiples descriptores de archivo para ver si alguno de ellos tiene eventos de interés (especificados en la estructura pollfd). Si uno o más eventos ocurren, poll() devuelve el número de descriptores de archivo con eventos (almacenado en poll_count). Si poll() falla, devuelve -1, y errno se establece para indicar el error
            if (poll_count == -1) {
                perror("poll");
                break;
            }

            for (size_t i = 0; i < pollfds.size(); ++i) {
                if (pollfds[i].revents & POLLIN) {
                    if (pollfds[i].fd == server_socket) {
//si fd = server_socket indica que el evento de lectura ocurrió en el socket del servidor, lo que indica una nueva conexión entrante
                        handle_new_connection();
                    } else {
//indica que el evento de lectura ocurrió en uno de los sockets de los clientes
                        handle_client_message(pollfds[i].fd);
                    }
                }
//pollfds[i].revents -> contiene los eventos que realmente ocurrieron en el descriptor de archivo pollfds[i].fd
//& POLLIN -> es una operación bit a bit que comprueba si el bit POLLIN está establecido en revents. POLLIN indica que hay datos disponibles para leer en el descriptor de archivo.
//si pollfds[i].revents & POLLIN es verdadero, significa que hay datos disponibles para leer en pollfds[i].fd
            }
        }
    }

private:
    int port;
    std::string password;
    int server_socket;
    std::vector<struct pollfd> pollfds;
    std::map<int, std::string> clients; // Map from socket to client nickname
    std::map<std::string, std::set<int> > channels; // Map from channel name to set of clients

    void handle_new_connection() {
        sockaddr_in client_addr;
//declara una variable client_addr de tipo struct sockaddr_in. Esta estructura se utilizará para almacenar la dirección del clientque se se conectará al servidor
        socklen_t client_len = sizeof(client_addr);
//socklen_t es un tipo definido para almacenar tamaños de direcciones de sockets. Inicializa client_len con el tamaño de la estructura client_addr. Esta variable se pasará a la función accept() para indicar el tamaño de la estructura client_addr y luego se actualizará para contener el tamaño real de la dirección del cliente
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
//accept() -> es una función de la API de sockets que acepta una nueva conexión entrante en un socket de escucha (server_socket)
//server_socket -> es el descriptor de archivo del socket de escucha del servidor
//(struct sockaddr*)&client_addr -> un puntero a la estructura sockaddr_in que almacenará la dirección del cliente. Se realiza un cast a struct sockaddr* porque accept() espera un puntero a struct sockaddr
//&client_len -> un puntero a client_len, que inicialmente contiene el tamaño de la estructura client_addr. accept() actualiza este valor para reflejar el tamaño real de la dirección del cliente
//si accept() falla devuelve -1
//RESUMEN DEL PROCESO
//accept espera una nueva conexión entrante en el socket del servidor (server_socket). Cuando llega una conexión, accept():
//- crea un nuevo socket para la conexión entrante
//- rellena client_addr con la dirección del cliente
//- actualiza client_len con el tamaño real de la dirección del cliente
//- devuelve un nuevo descriptor de archivo (client_socket) que se puede usar para comunicarse con el cliente

        if (client_socket == -1) {
            perror("accept");
            return;
        }

        // Configurar el socket del cliente como no bloqueante
        int flags = fcntl(client_socket, F_GETFL, 0);
        if (flags == -1 || fcntl(client_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
            perror("fcntl");
            close(client_socket);
            return;
        }

        struct pollfd pfd;
        pfd.fd = client_socket;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pollfds.push_back(pfd);
        clients[client_socket] = "";
//se agrega al map clients con el nombre vacío

        std::cout << "New connection accepted" << std::endl;
    }

    void handle_client_message(int client_socket) {
        char buffer[BUFFER_SIZE];
        int bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);

        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                std::cout << "Client disconnected" << std::endl;
            } else {
                perror("read");
            }

            close(client_socket);
            remove_client(client_socket);
            return;
        }

        buffer[bytes_read] = '\0';
        std::string message(buffer);

        if (message.substr(0, 5) == "NICK ") {
            clients[client_socket] = message.substr(5);
        } else if (message.substr(0, 5) == "JOIN ") {
            std::string channel = message.substr(5);
            channels[channel].insert(client_socket);
        } else if (message.substr(0, 5) == "PART ") {
            std::string channel = message.substr(5);
            channels[channel].erase(client_socket);
            if (channels[channel].empty()) {
                channels.erase(channel);
            }
        } else if (message.substr(0, 5) == "KICK ") {
            // Handle KICK command
        } else if (message.substr(0, 7) == "INVITE ") {
            // Handle INVITE command
        } else if (message.substr(0, 6) == "TOPIC ") {
            // Handle TOPIC command
        } else if (message.substr(0, 5) == "MODE ") {
            // Handle MODE command
        } else {
            // Broadcast message to all clients in the channel
            std::map<std::string, std::set<int> >::iterator it;
            for (it = channels.begin(); it != channels.end(); ++it) {
                if (it->second.find(client_socket) != it->second.end()) {
                    std::set<int>::iterator client_it;
                    for (client_it = it->second.begin(); client_it != it->second.end(); ++client_it) {
                        if (*client_it != client_socket) {
                            send(*client_it, message.c_str(), message.size(), 0);
                        }
                    }
                }
            }
        }
    }

    void remove_client(int client_socket) {
        std::vector<struct pollfd>::iterator it;
        for (it = pollfds.begin(); it != pollfds.end(); ++it) {
            if (it->fd == client_socket) {
                pollfds.erase(it);
                break;
            }
        }
        clients.erase(client_socket);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <port> <password>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);
    std::string password = argv[2];

    IRCServer server(port, password);
    if (!server.start()) {
        return 1;
    }

    server.run();
    return 0;
}
