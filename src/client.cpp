#include "includes.h"
#include "common.h"

#include <cstdio>
#include <openssl/sha.h>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <algorithm>

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
#define MAX_DOWNLOADS       100

static int cursor_r_pos;
static int cursor_c_pos;
static int cursor_left_limit;
static int cursor_right_limit;
string working_dir;
static struct termios prev_attr, new_attr;

multimap<string, string> seeding_files_multimap;

static bool is_status_on;

static string log_file_path, seeding_file_path, client_exec_path;
static string addr[3];
static string ip[3];
static int port[3];
static int curr_tracker_id;
static mutex download_mtx[MAX_DOWNLOADS];
static bool mtx_inuse[MAX_DOWNLOADS];


enum operation
{
    ADD,
    REMOVE
};

enum client_to_tracker_req
{
    SHARE,
    GET,
    REMOVE_TORRENT
};

enum client_to_client_req
{
    GET_CHUNK_IDS,
    GET_CHUNKS
};

void ip_and_port_split(string addr, string &ip, int &port);

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


int download_id_get()
{
    for(int i = 0; i < MAX_DOWNLOADS; ++i)
    {
        if(!mtx_inuse[i])
            return i;
    }
    return FAILURE;
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

int make_connection_with_tracker()
{
    int sock = make_connection(ip[curr_tracker_id], port[curr_tracker_id]);

    if(FAILURE == sock)
    {
        curr_tracker_id = (curr_tracker_id == TRACKER1) ? TRACKER2 : TRACKER1;
        sock = make_connection(ip[curr_tracker_id], port[curr_tracker_id]);
        if(FAILURE == sock)
        {
            string err_str = "Error: ";
            err_str = err_str + strerror(errno);
            status_print(FAILURE, err_str);
            return FAILURE;
        }
    }
    return sock;
}

int send_request(int sock, int req, string str)
{
    #if 0
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
    #endif

    string req_op = to_string(req);
    str = req_op + "$" + str;
    send(sock, str.c_str(), str.length(), 0); 

    fprint_log("Sent req to tracker: " + str);
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

int share_request(vector<string> &cmd)
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

    int sock = make_connection_with_tracker();
    if(FAILURE == sock)
    {
        return FAILURE;
    }
    send_request(sock, SHARE, double_sha1_str + "$" + addr[CLIENT] + "$" + local_file_name);
    close(sock);
    status_print(SUCCESS, "SUCCESS: " + cmd[2]);
    return SUCCESS;
}

void do_join(thread& t)
{
    t.join();
}

void join_all(vector<thread>& v)
{
    for_each(v.begin(), v.end(), do_join);
}

void file_chunk_ids_get(string seeder_addr, string double_sha1_str, vector<vector<int>>& chunk_ids_vec, int download_id)
{
    string seeder_ip;
    int seeder_port;
    ip_and_port_split(seeder_addr, seeder_ip, seeder_port);
    int sock = make_connection(seeder_ip, seeder_port);

    send_request(sock, GET_CHUNK_IDS, double_sha1_str);

    char file_chunk_ids[4096] = {'\0'};
    read(sock, file_chunk_ids, sizeof(file_chunk_ids) - 1);
    close(sock);

    string chunk_ids(file_chunk_ids);
    int dollar_pos, id;
    vector<int> ids_vec;
    while((dollar_pos = chunk_ids.find('$')) != string::npos)
    {
        id = stoi(chunk_ids.substr(0, dollar_pos));
        ids_vec.push_back(id);
        chunk_ids.erase(0, dollar_pos);
    }
    id = stoi(chunk_ids);
    ids_vec.push_back(id);

    lock_guard<mutex> lg(download_mtx[download_id]);
    chunk_ids_vec.push_back(ids_vec);
}

void chunks_download(string reqd_ids_str, string seeder_addr, string dest_file_path, int download_id)
{
    string seeder_ip;
    int seeder_port, dollar_pos, id;
    ip_and_port_split(seeder_addr, seeder_ip, seeder_port);

    int sock = make_connection(seeder_ip, seeder_port);
    if(FAILURE == sock)
        return;

    send_request(sock, GET_CHUNKS, reqd_ids_str);

    ofstream out(dest_file_path);
    if(!out)
    {
        string err_str = "Error: ";
        err_str = err_str + strerror(errno);
        status_print(FAILURE, err_str);
        return;
    }
    while((dollar_pos = reqd_ids_str.find('$')) != string::npos)
    {
        id = stoi(reqd_ids_str.substr(0, dollar_pos));
        reqd_ids_str.erase(0, dollar_pos);

        char downloaded_chunk[PIECE_SIZE + 1] = {'\0'};
        read(sock, downloaded_chunk, sizeof(downloaded_chunk) - 1);

        {
            lock_guard<mutex> lg(download_mtx[download_id]);
            out.seekp(id * PIECE_SIZE, ios::beg);
            out.write(downloaded_chunk, PIECE_SIZE);
        }
    }
    id = stoi(reqd_ids_str);

    char downloaded_chunk[PIECE_SIZE + 1] = {'\0'};
    read(sock, downloaded_chunk, sizeof(downloaded_chunk) - 1);

    {
        lock_guard<mutex> lg(download_mtx[download_id]);
        out.seekp(id * PIECE_SIZE, ios::beg);
        out.write(downloaded_chunk, PIECE_SIZE);
    }

    close(sock);
}

void file_download(string double_sha1_str, string seeder_addrs, unsigned long long filesize, string dest_file_path, int download_id)
{
    int dollar_pos;
    string addr;
    vector<thread>      seeder_thread_vec;
    vector<vector<int>> seeder_chunk_ids;
    vector<string>      seeder_addr_vec;

    int nchunks;
    if(filesize % PIECE_SIZE)
        nchunks = (filesize / PIECE_SIZE) + 1;
    else
        nchunks = filesize / PIECE_SIZE;

    string ip;
    int port;
    while((dollar_pos = seeder_addrs.find('$')) != string::npos)
    {
        addr = seeder_addrs.substr(0, dollar_pos);
        seeder_addr_vec.push_back(addr);
        seeder_addrs.erase(0, dollar_pos);

        thread th(file_chunk_ids_get, addr, double_sha1_str, ref(seeder_chunk_ids), download_id);
        seeder_thread_vec.push_back(move(th));
    }
    thread th(file_chunk_ids_get, seeder_addrs, double_sha1_str, ref(seeder_chunk_ids), download_id);
    seeder_thread_vec.push_back(move(th));
    join_all(seeder_thread_vec);

    int nseeders = seeder_chunk_ids.size();
    int idx[nseeders] = {0};
    bool alldone = false;

    for(int i = 0; i < nseeders; ++i)
    {
        sort(seeder_chunk_ids[i].begin(), seeder_chunk_ids[i].end());
    }
    bool visited[nchunks] = {0};
    vector<string> distributed_ids(nseeders);

    while(!alldone)
    {
        alldone = true;
        for(int i = 0; i < nseeders; ++i)
        {
            vector<int> &id_vec = seeder_chunk_ids[i];
            int sz = id_vec.size();
            while(idx[i] < sz && visited[id_vec[idx[i]]])
                ++idx[i];

            if(idx[i] < sz)
            {
                alldone = false;
                visited[id_vec[idx[i]]] = true;
                distributed_ids[i] += to_string(id_vec[idx[i]]);
                ++idx[i];
                if(idx[i] < sz)
                    distributed_ids[i] += "$";
            }
        }
    }

    seeder_thread_vec.clear();

    // block created to restrict the scope of "out" variable
    {
        // create an empty file of size "filesize"
        ofstream out(dest_file_path);
        out.seekp(filesize);
        out << '\0';
    }

    for(int i = 0; i < nseeders; ++i)
    {
        if(!distributed_ids[i].empty())
        {
            thread th(chunks_download, distributed_ids[i], seeder_addr_vec[i], dest_file_path, download_id);
            seeder_thread_vec.push_back(move(th));
        }
    }
    join_all(seeder_thread_vec);
    mtx_inuse[download_id] = false;
}

int get_request(vector<string> &cmd)
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
    while(line_no != 4 && getline(in, line_str))
        ++line_no;

    int nchunks = 0;
    unsigned long long filesize = 0;
    if(line_no == 4)    // filesize
    {
        filesize = stoi(line_str);
        if(filesize % PIECE_SIZE)
            nchunks = (filesize / PIECE_SIZE) + 1;
        else
            nchunks = filesize / PIECE_SIZE;

        getline(in, line_str);
        ++line_no;
    }

    string double_sha1_str;
    if(line_no == 5)    // sha1 string
    {
        double_sha1_str = get_sha1_str((const unsigned char*)line_str.c_str(), line_str.length());
    }

    int sock = make_connection_with_tracker();
    send_request(sock, GET, double_sha1_str);

    char seeder_list[4096] = {'\0'};
    read(sock, seeder_list, sizeof(seeder_list) - 1);
    close(sock);

    int download_id = download_id_get();
    mtx_inuse[download_id] = true;
    thread download_thread(file_download, double_sha1_str, seeder_list, filesize, dest_file_path, download_id);
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
            share_request(command);
        }
        else if(command[0] == "get")
        {
            if(FAILURE == command_size_check(command, 3, 3, "get: (usage):- \"get <local_file_path>"
                                                            " <path_to_.mtorrent_file> <destination_path>\""))
                continue;
            get_request(command);
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
