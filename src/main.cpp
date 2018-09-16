#include "includes.h"
#include "common.h"

#include <cstdio>
#include <openssl/sha.h>
#include <vector>

using namespace std;

#define PIECE_SIZE    (512 * 1024)
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
string root_dir;
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

#if 0
void from_cursor_line_clear()
{
    cout << "\e[0K";
    cout.flush();
}
#endif

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

    //streampos pos;
    ifstream infile (local_file_path.c_str(), ios::binary | ios::in);
    infile.seekg(0, ios::end);
    total_bytes = infile.tellg();
    //total_bytes = pos;

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

    cout << sha1_str.length() << endl;
    cout << sha1_str << endl;
    cout << "Total bytes read = " << bytes_read << endl;
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
        #if 0
        else if(command[0] == "move")
        {
            if(FAILURE == command_size_check(command, 3, INT_MAX, "move: (usage):- \"move <source_file/dir(s)>"
                                                                  " <destination_directory>\""))
                continue;
            move_command(command);
        }
        else if(command[0] == "rename")
        {
            if(FAILURE == command_size_check(command, 3, 3, "rename: (usage):- \"rename <source_file/dir>"
                                                             " <destination_file/dir>\""))
                continue;
            
            string old_path = abs_path_get(command[1]);
            string new_path = abs_path_get(command[2]);
            if(is_directory(old_path))
            {
                if(!dir_exists(old_path))
                {
                    status_print(command[1] + " doesn't exist!!");
                    continue;
                }
                if(dir_exists(new_path))
                {
                    status_print(command[2] + " already exists!!");
                    continue;
                }
            }
            else
            {
                if(!file_exists(old_path))
                {
                    status_print(command[1] + " doesn't exist!!");
                    continue;
                }
                if(file_exists(new_path))
                {
                    status_print(command[2] + " already exists!!");
                    continue;
                }
            }
            if(FAILURE == rename(old_path.c_str(), new_path.c_str()))
            {
                status_print("rename failed!! errno: " + to_string(errno));
            }
            else
            {
                display_refresh();
            }
        }
        else if(command[0] == "create_file")
        {
            if(FAILURE == command_size_check(command, 3, 3, "create_file: (usage):- \"create_file <new_file>"
                                                             " <destination_dir>\""))
                continue;

            string dest_path = abs_path_get(command[2]);
            if(dest_path[dest_path.length() - 1] != '/')
                dest_path = dest_path + "/";

            if(!dir_exists(dest_path))
            {
                status_print(command[2] + " doesn't exists!!");
                continue;
            }
            dest_path += command[1];
            if(file_exists(dest_path))
            {
                status_print(command[1] + " already exists at " + command[2]);
                continue;
            }

            int fd = open(dest_path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
            if(FAILURE == fd)
            {
                status_print( "open failed!! errno: " + to_string(errno));
            }
            else
            {
                close(fd);
                display_refresh();
            }
        }
        else if(command[0] == "create_dir")
        {
            if(FAILURE == command_size_check(command, 3, 3, "create_dir: (usage):- \"create_dir <new_dir>"
                                                             " <destination_dir>\""))
                continue;

            string dest_path = abs_path_get(command[2]);
            if(dest_path[dest_path.length() - 1] != '/')
                dest_path = dest_path + "/";

            if(!dir_exists(dest_path))
            {
                status_print(command[2] + " doesn't exists!!");
                continue;
            }
            dest_path += command[1];
            if(dir_exists(dest_path))
            {
                status_print(command[1] + " already exists at " + command[2]);
                continue;
            }
            if(FAILURE == mkdir(dest_path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
            {
                status_print("mkdir failed!! errno: " + to_string(errno));
            }
            else
            {
                display_refresh();
            }
        }
        else if(command[0] == "delete_file")
        {
            if(FAILURE == command_size_check(command, 2, 2, "delete_file: (usage):- \"delete_file <file_path>\""))
                continue;

            string rem_path = abs_path_get(command[1]);
            if(!file_exists(rem_path))
            {
                status_print(command[1] + " doesn't exists!!");
                continue;
            }
            
            if(FAILURE == unlinkat(0, rem_path.c_str(), 0))
            {
                status_print("unlinkat failed!! errno: " + to_string(errno));
            }
            else
            {
               display_refresh();
            }
        }
        else if(command[0] == "delete_dir")
        {
            if(FAILURE == command_size_check(command, 2, 2, "delete_dir: (usage):- \"delete_dir <directory_path>\""))
                continue;

            string rem_path = abs_path_get(command[1]);
            if(!dir_exists(rem_path))
            {
                status_print(command[1] + " doesn't exist!!");
                continue;
            }
            delete_command(rem_path);
        }
        else if(command[0] == "goto")
        {
            if(FAILURE == command_size_check(command, 2, 2, "goto: (usage):- \"goto <directory_path>\""))
                continue;

            string dest_path = abs_path_get(command[1]);
            if(!dir_exists(dest_path))
            {
                status_print(command[1] + " doesn't exist!!");
                continue;
            }
            if(dest_path[dest_path.length() - 1] != '/')
                dest_path = dest_path + "/";

            if(dest_path == working_dir)
            {
                status_print("Current directory and Destination directory are the same!!");
                continue;
            }
            stack_clear(fwd_stack);
            bwd_stack.push(working_dir);

            working_dir = dest_path;
            display_refresh();
        }
        else if(command[0] == "search")
        {
            if(FAILURE == command_size_check(command, 2, 2, "search: (usage):- \"search <directory/file_path>\""))
                continue;

            search_str = command[1];
            content_list.clear();
            nftw(working_dir.c_str(), search_cb, ftw_max_fd, 0);
            if(content_list.empty())
            {
                status_print("No match found!!");
                continue;
            }
            is_search_content = true;
            stack_clear(fwd_stack);
            break;
        }
        else if(command[0] == "snapshot")
        {
            if(FAILURE == command_size_check(command, 3, 3, "snapshot: (usage):- \"snapshot <folder> <dumpfile>\""))
                continue;

            snapshot_folder_path = abs_path_get(command[1]);
            if(!dir_exists(snapshot_folder_path))
            {
                status_print(command[1] + " doesn't exist!!");
                continue;
            }
            dumpfile_path = abs_path_get(command[2]);
            ofstream dumpfile (dumpfile_path.c_str(), ios::out | ios::trunc);
            dumpfile.close();
            if(snapshot_folder_path[snapshot_folder_path.length() - 1] == '/')
                snapshot_folder_path.erase(snapshot_folder_path.length() - 1);

            nftw(snapshot_folder_path.c_str(), snapshot_cb, ftw_max_fd, 0);
            display_refresh();
        }
        #endif
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
    root_dir = getenv("PWD");
    if(root_dir != "/")
        root_dir = root_dir + "/";
    working_dir = root_dir;

    client_addr = argv[1];
    tracker1_addr = argv[2];
    tracker2_addr = argv[3];
    log_file_path = argv[4];

    enter_command();
    cin.get();

    tcsetattr( STDIN_FILENO, TCSANOW, &prev_attr);
    return 0;
}
