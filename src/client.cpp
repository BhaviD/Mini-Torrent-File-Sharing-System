#include "includes.h"
#include "common.h"

#include <cstdio>
#include <openssl/sha.h>
#include <vector>
#include <map>

// Client side C/C++ program to demonstrate Socket programming 
#include <sys/socket.h> 
#include <cstdlib> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <string.h> 

using namespace std;

#define PIECE_SIZE     (512 * 1024)
#define pb             push_back

#define FAILURE             -1
#define SUCCESS             0
#define ENTER               10
#define ESC                 27
#define UP                  11
#define DOWN                12
#define RIGHT               13
#define LEFT                14
#define BACKSPACE           127
#define SEEDING_FILES_LIST  ("seeding_files.txt")
#define TRACKER1            0
#define TRACKER2            1
#define CLIENT              2

static int cursor_r_pos;
static int cursor_c_pos;
static int cursor_left_limit;
static int cursor_right_limit;
string working_dir;
static struct termios prev_attr, new_attr;

multimap<string, string> seeding_files_multimap;

static bool is_status_on;

static string log_file_path, seeding_file_path, client_exec_path;
//static string client_addr, tracker1_addr, tracker2_addr;
//static string tracker1_ip, tracker2_ip, client_ip;
//static int tracker1_port, tracker2_port, client_port;
static string addr[3];
static string ip[3];
static int port[3];
static int curr_tracker_id;


enum operation
{
    ADD,
    REMOVE
};

enum client_request
{
    SHARE,
    GET,
    REMOVE_TORRENT
};

void cursor_init()
{
    cout << "\033[" << cursor_r_pos << ";" << cursor_c_pos << "H";
    cout.flush();
}

void screen_clear()
{
    cout << "\033[3J" << "\033[H\033[J";
    cout.flush();
    cursor_r_pos = cursor_c_pos = 1;
    cursor_init();
}

void print_mode()
{
    cursor_r_pos = 1;
    cursor_c_pos = 1;
    cursor_init();
    from_cursor_line_clear();

    stringstream ss;
    ss << "[Enter Command] :";

    cout << "\033[1;33;40m" << ss.str() << "\033[0m" << " ";    // YELLOW text and BLACK background
    cout.flush();
    cursor_c_pos = ss.str().length() + 2;       // two spaces
    cursor_init();
    cursor_left_limit = cursor_right_limit = cursor_c_pos;
}

void status_print(int result, string msg)
{
    if(is_status_on)
        return;

    is_status_on = true;
    cursor_c_pos = cursor_left_limit;
    cursor_init();

    from_cursor_line_clear();
    if(FAILURE == result)
        cout << "\033[1;31m" << msg << "\033[0m";	// RED color
    else
        cout << "\033[1;32m" << msg << "\033[0m";	// GREEN color

    cout.flush();
}

string current_timestamp_get()
{
    time_t tt;
    struct tm *ti;

    time (&tt);
    ti = localtime(&tt);
    return asctime(ti);
}

void fprint_log(string msg)
{
    ofstream out(log_file_path, ios_base::app);
    if(!out)
    {
        string err_str = "Error: ";
        err_str = err_str + strerror(errno);
        status_print(FAILURE, err_str);
        return;
    }
    string curr_timestamp = current_timestamp_get();
    curr_timestamp.pop_back();
    out << curr_timestamp << " : " << "\"" << msg << "\"" << "\n";
}


int command_size_check(vector<string> &v, unsigned int min_size, unsigned int max_size, string error_msg)
{
    if(v.size() < min_size || v.size() > max_size)
    {
        status_print(FAILURE, error_msg);
        return FAILURE;
    }
    return SUCCESS;
}

int make_connection(string ip, uint16_t port)
{
    struct sockaddr_in serv_addr; 
    int sock = 0;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        status_print(FAILURE, "Socket connection error!!");
        return FAILURE; 
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr)<=0)  
    { 
        status_print(FAILURE, "Invalid address/ Address not supported");
        return FAILURE;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        status_print(FAILURE, "Connection with tracker failed!!");
        return FAILURE; 
    } 
 
    return sock;
}

int send_req_to_tracker(client_request req, string str)
{
    int sock = make_connection(ip[curr_tracker_id], port[curr_tracker_id]);

    if(FAILURE == sock)
    {
        curr_tracker_id = (curr_tracker_id == TRACKER1) ? TRACKER2 : TRACKER1;
        sock = make_connection(ip[curr_tracker_id], port[curr_tracker_id]);
        if(FAILURE == sock)
        {
            return FAILURE;
        }
    }

    string req_op = to_string(req);
    str = req_op + "$" + str;
    send(sock, str.c_str(), str.length(), 0); 

    fprint_log("Sent req to tracker: " + str);

    if(GET == req)
    {
        char buff[4096] = {'\0'};
        read(sock, buff, sizeof(buff) - 1);

        string seeder_addrs(buff);
        cout << seeder_addrs << endl;
    }

    close(sock);

    return SUCCESS;
}

void update_seeding_file(operation opn, string sha1_str, string file_path)
{
    switch(opn)
    {
        case ADD:
        {
            seeding_files_multimap.insert({sha1_str, file_path});

            ofstream out(seeding_file_path + SEEDING_FILES_LIST, ios_base::app);
            out << sha1_str << "$" << file_path << "\n";
            break;
        }
        case REMOVE:
            /* TODO: create a thread and remove the file from seeding_files.txt */
            break;
        default:
            break;
    }
}

string get_sha1_str(const unsigned char* ibuf, int blen)
{
    char sha1_buff[3] = {'\0'};
    unsigned char obuf[21] = {'\0'};
    string str;

    SHA1(ibuf, blen, obuf);
    for (int i = 0; i < 10; i++) {
        snprintf(sha1_buff, sizeof(sha1_buff), "%02x", obuf[i]);
        str = str + sha1_buff;			// str becomes a string of 40 characters
    }
    return str;
}

int share_command(vector<string> &cmd)
{
    string str;
    string local_file_path, mtorrent_file_path;
    local_file_path = abs_path_get(cmd[1]);
    mtorrent_file_path = abs_path_get(cmd[2]);

    int bytes_read, total_bytes_read = 0;
    bool read_done = false;
    string sha1_str;

    ifstream infile (local_file_path.c_str(), ios::binary | ios::in);
    if(!infile)
    {
        string err_str = "FAILURE: ";
        err_str = err_str + strerror(errno);
        status_print(FAILURE, err_str);
        return FAILURE;
    }

    while(infile)
    {
        unsigned char ibuf[PIECE_SIZE + 1] = {'\0'};
        infile.read((char*)ibuf, PIECE_SIZE);

        if(infile.fail() && !infile.eof())
        {
            string err_str = "Error: ";
            err_str = err_str + strerror(errno);
            status_print(FAILURE, err_str);
            return FAILURE;
        }

        bytes_read = infile.gcount();
        total_bytes_read += bytes_read;

        sha1_str += get_sha1_str(ibuf, bytes_read);            // taking the first 20 characters
    }

    ofstream out(mtorrent_file_path, ios::out);
    int pos = local_file_path.find_last_of("/");
    string local_file_name = local_file_path.substr(pos+1);
    if(out)
    {
        out << addr[TRACKER1] << "\n";
        out << addr[TRACKER2] << "\n";
        out << local_file_path << "\n";
        out << total_bytes_read << "\n";
        out << sha1_str << "\n";
    }

    // applying SHA1 on already created SHA1 string.
    string double_sha1_str = get_sha1_str((const unsigned char*)sha1_str.c_str(), sha1_str.length());
    update_seeding_file(ADD, double_sha1_str, local_file_path);
    send_req_to_tracker(SHARE, double_sha1_str + "$" + addr[CLIENT] + "$" + local_file_name);

    status_print(SUCCESS, "SUCCESS: " + cmd[2]);
    return SUCCESS;
}

int get_command(vector<string> &cmd)
{
    string mtorrent_file_path = abs_path_get(cmd[1]);
    string dest_file_path = abs_path_get(cmd[2]);

    ifstream in(mtorrent_file_path);
    if(!in)
    {
        string err_str = "Error: ";
        err_str = err_str + strerror(errno);
        status_print(FAILURE, err_str);
        return FAILURE;
    }

    int line_no = 0;
    string line_str;
    while(line_no != 5 && getline(in, line_str))
    {
        ++line_no;
    }
    if(line_no == 5)
    {
        string double_sha1_str = get_sha1_str((const unsigned char*)line_str.c_str(), line_str.length());
        send_req_to_tracker(GET, double_sha1_str);
    }
}

void enter_commands()
{
    bool command_exit = false;

    while(1)
    {
        if(!is_status_on)
            print_mode();

        char ch;
        string cmd;
        bool enter_pressed = false;
        while(!enter_pressed && !command_exit)
        {
            ch = next_input_char_get();
            if(is_status_on)
            {
                is_status_on = false;
                cursor_c_pos = cursor_left_limit;
                cursor_init();
                from_cursor_line_clear();
            }
            switch(ch)
            {
                case ESC:
                    command_exit = true;
                    break;

                case ENTER:
                    enter_pressed = true;
                    break;

                case BACKSPACE:
                    if(cmd.length())
                    {
                        --cursor_c_pos;
                        --cursor_right_limit;
                        cursor_init();
                        from_cursor_line_clear();
                        cmd.erase(cursor_c_pos - cursor_left_limit, 1);
                        cout << cmd.substr(cursor_c_pos - cursor_left_limit);
                        cout.flush();
                        cursor_init();
                    }
                    break;

                case UP:
                case DOWN:
                    break;

                case LEFT:
                    if(cursor_c_pos != cursor_left_limit)
                    {
                        --cursor_c_pos;
                        cursor_init();
                    }
                    break;

                case RIGHT:
                    if(cursor_c_pos != cursor_right_limit)
                    {
                        ++cursor_c_pos;
                        cursor_init();
                    }
                    break;

                default:
                    cmd.insert(cursor_c_pos - cursor_left_limit, 1, ch);
                    cout << cmd.substr(cursor_c_pos - cursor_left_limit);
                    cout.flush();
                    ++cursor_c_pos;
                    cursor_init();
                    ++cursor_right_limit;
                    break;
            }
        }
        if(command_exit)
            break;

        if(cmd.empty())
            continue;

        string part;
        vector<string> command;

        for(unsigned int i = 0; i < cmd.length(); ++i)
        {
            if(cmd[i] == ' ')
            {
                if(!part.empty())
                {
                    command.pb(part);
                    part = "";
                }
            }
            else if(cmd[i] == '\\' && (i < cmd.length() - 1) && cmd[i+1] == ' ')
            {
                part += ' ';
                ++i;
            }
            else
            {
                part += cmd[i];
            }
        }
        if(!part.empty())
            command.pb(part);

        if(command.empty())
            continue;

        if(command[0] == "exit")
            break;

        if(command[0] == "share")
        {
            if(FAILURE == command_size_check(command, 3, 3, "share: (usage):- \"share <local_file_path>"
                                                            " <filename>.<file_extension>.mtorrent\""))
                continue;
            share_command(command);
        }
        else if(command[0] == "get")
        {
            if(FAILURE == command_size_check(command, 3, 3, "get: (usage):- \"get <local_file_path>"
                                                            " <path_to_.mtorrent_file> <destination_path>\""))
                continue;
            get_command(command);
        }
        else
        {
            status_print(FAILURE, "Invalid Command. Please try again!!");
        }
    }
}


void ip_and_port_split(string addr, string &ip, int &port)
{
    int colon_pos = addr.find(':');
    if(colon_pos != string::npos)
    {
        ip = addr.substr(0, colon_pos);
        port = stoi(addr.substr(colon_pos + 1));
    }
}

int main(int argc, char* argv[])
{
    screen_clear();

    tcgetattr(STDIN_FILENO, &prev_attr);
    new_attr = prev_attr;
    new_attr.c_lflag &= ~ICANON;
    new_attr.c_lflag &= ~ECHO;
    tcsetattr( STDIN_FILENO, TCSANOW, &new_attr);

    if(argc < 5 || argc > 5)
    {
        status_print(FAILURE, "Client Application Usage: \"/executable <CLIENT_IP>:<UPLOAD_PORT>"
                     " <TRACKER_IP_1>:<TRACKER_PORT_1> <TRACKER_IP_2>:<TRACKER_PORT_2> <log_file>\"");
        cout << endl;
        tcsetattr( STDIN_FILENO, TCSANOW, &prev_attr);
        return 0;
    }

    print_mode();
    working_dir = getenv("PWD");
    if(working_dir != "/")
        working_dir = working_dir + "/";

    client_exec_path = abs_path_get(argv[0]);
    int pos = client_exec_path.find_last_of("/");
    seeding_file_path = client_exec_path.substr(0, pos+1);

    addr[CLIENT] = argv[1];
    addr[TRACKER1] = argv[2];
    addr[TRACKER2] = argv[3];
    log_file_path = abs_path_get(argv[4]);

    ip_and_port_split(addr[CLIENT], ip[CLIENT], port[CLIENT]);
    ip_and_port_split(addr[TRACKER1], ip[TRACKER1], port[TRACKER1]);
    ip_and_port_split(addr[TRACKER2], ip[TRACKER2], port[TRACKER2]);

    curr_tracker_id = TRACKER1;

    enter_commands();
    screen_clear();

    tcsetattr( STDIN_FILENO, TCSANOW, &prev_attr);
    return 0;
}
