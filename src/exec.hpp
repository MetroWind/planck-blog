// Usage: See the Exec.CanPipeWithPipes and Exec.CanPipeWithString
// unit tests.

#pragma once

#include <array>
#include <initializer_list>
#include <string>
#include <variant>

#include "error.hpp"

// A thin wrapper around the POSIX pipe utilities. Here “input” means
// the end which data flows into the pipe, and “output” means the end
// which data flows out of the pipe.
class Pipe
{
public:
    // Do not use. Does not actually do anything.
    Pipe() = default;
    Pipe(const Pipe&) = delete;
    Pipe(Pipe&& rhs);
    Pipe& operator=(const Pipe&) = delete;
    Pipe& operator=(Pipe&& rhs);

    static E<Pipe> create();

    // This class does not keep track of duped FDs. If you have
    // duplicateded an end, destroying the Pipe object does not always
    // mean the destruction of the actual pipe.
    ~Pipe();

    E<void> closeInput();
    E<void> closeOutput();
    E<int> dupInput(int fd) const;
    E<int> dupOutput(int fd) const;

    int inputFD() const { return fds[1]; }
    int outputFD() const { return fds[0]; }

    E<std::string> read() const;
    E<void> write(std::string_view data) const;

private:
    // an array that will hold two file descriptors
    std::array<int, 2> fds = {-1, -1};
    bool output_closed = true;
    bool input_closed = true;
};

// Doesn’t support using a pipe to connect two Processes yet.
struct Process
{
public:
    using None = std::nullptr_t;
    using Input = std::variant<None, std::string_view, Pipe*>;
    using Output = std::variant<None, std::string*, Pipe*>;
    // Do not use. Does not actually do anything.
    Process() = default;
    // Start a child process with “args”.
    static E<Process> exec(
        const Input input, std::initializer_list<const char*> args,
        const Output output);

    Process(const Process&) = delete;
    Process(Process&& rhs);
    Process& operator=(const Process&) = delete;
    Process& operator=(Process&& rhs);

    ~Process();

    // Wait for the child process to finish. Obviously this must be
    // called after calling exec(). Also it must be called exactly
    // once.
    E<int> wait();

private:
    // Stores the PID of the child.
    pid_t pid = 0;
    // This is used to let the child tell the parent when execvp
    // fails. This could probably be replaced with either shard mem or
    // a message queue.
    Pipe comm;
    // Save the output parameter of the exec() call, so that the
    // output pipe/string can be manipulated in wait().
    Output output = nullptr;
    // If the output is a string, we will use this to pipe the output
    // to the string.
    Pipe managed_output_pipe;
};
