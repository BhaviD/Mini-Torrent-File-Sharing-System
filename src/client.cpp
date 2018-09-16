#include "includes.h"
#include "common.h"

#include <cstdio>
#include <openssl/sha.h>
#include <vector>

using namespace std;

#define PIECE_SIZE     (512 * 1024)
#define pb             push_back

#define FAILURE        -1
#define SUCCESS        0
#define ENTER          10
#define ESC            27
#define UP             11
#define DOWN           12
#define RIGHT          13
#define LEFT           14
#define BACKSPACE      127

static int cursor_r_pos;
static int cursor_c_pos;
static int cursor_left_limit;
static int cursor_right_limit;
string working_dir;
struct termios prev_attr, new_attr;

static bool is_status_on;

string client_addr, log_file_path;
string tracker1_addr, tracker2_addr;

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

void status_print(string msg)
{
    if(is_status_on)
        return;

    is_status_on = true;
    cursor_c_pos = cursor_left_limit;
    cursor_init();

    from_cursor_line_clear();
    cout << "\033[1;31m" << msg << "\033[0m";	// RED color
    cout.flush();
}

int command_size_check(vector<string> &v, unsigned int min_size, unsigned int max_size, string error_msg)
{
    if(v.size() < min_size || v.size() > max_size)
    {
        status_print(error_msg);
        return FAILURE;
    }
    return SUCCESS;
}

int share_command(vector<string> &cmd)
{
    string local_file_path, mtorrent_file_path;
    local_file_path = abs_path_get(cmd[1]);
    mtorrent_file_path = abs_path_get(cmd[2]);

    unsigned char obuf[21] = {'\0'};
    char sha1_buff[3] = {'\0'};
    int total_bytes, bytes_read = 0;
    bool read_done = false;
    string sha1_str;

    ifstream infile (local_file_path.c_str(), ios::binary | ios::in);
    infile.seekg(0, ios::end);
    total_bytes = infile.tellg();

    int read_size;
    while(!read_done)
    {
        infile.seekg(bytes_read, infile.beg);
        if(total_bytes - bytes_read > PIECE_SIZE)
            read_size = PIECE_SIZE;
        else
        {
            read_size = total_bytes - bytes_read;
            read_done = true;
        }

        unsigned char ibuf[PIECE_SIZE + 1] = {'\0'};
        infile.read((char*)ibuf, read_size);
        SHA1(ibuf, strlen((const char*)ibuf), obuf);

        string str;
        for (int i = 0; i < 20; i++) {
            snprintf(sha1_buff, sizeof(sha1_buff), "%02x", obuf[i]);
            str = str + sha1_buff;					// str becomes a string of 40 characters
        }
        sha1_str = sha1_str + str.substr(0, 20);			// taking the first 20 characters
        bytes_read += read_size;
    }

    ofstream out(mtorrent_file_path, ios::out);
    int pos = local_file_path.find_last_of("/");
    if(out)
    {
        out << tracker1_addr << "\n";
        out << tracker2_addr << "\n";
        out << local_file_path.substr(pos+1) << "\n";
        out << total_bytes << "\n";
        out << sha1_str << "\n";
    }
    //cout << sha1_str.length() << endl;
    //cout << sha1_str << endl;
    //cout << "Total bytes read = " << bytes_read << endl;
    return 0;
}

void enter_command()
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

        if(command[0] == "share")
        {
            if(FAILURE == command_size_check(command, 3, 3, "share: (usage):- \"share <local_file_path>"
                                                            " <filename>.<file_extension>.mtorrent\""))
                continue;
            share_command(command);
        }
        else
        {
            status_print("Invalid Command. Please try again!!");
        }
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
        status_print("Client Application Usage: \"/executable <CLIENT_IP>:<UPLOAD_PORT>"
                     " <TRACKER_IP_1>:<TRACKER_PORT_1> <TRACKER_IP_2>:<TRACKER_PORT_2> <log_file>\"");
        cout << endl;
        tcsetattr( STDIN_FILENO, TCSANOW, &prev_attr);
        return 0;
    }

    print_mode();
    working_dir = getenv("PWD");
    if(working_dir != "/")
        working_dir = working_dir + "/";

    client_addr = argv[1];
    tracker1_addr = argv[2];
    tracker2_addr = argv[3];
    log_file_path = argv[4];

    enter_command();
    cin.get();

    tcsetattr( STDIN_FILENO, TCSANOW, &prev_attr);
    return 0;
}
