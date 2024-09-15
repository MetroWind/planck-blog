#include <array>
#include <format>
#include <expected>
#include <utility>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include "error.hpp"
#include "exec.hpp"
#include "utils.hpp"

Pipe::Pipe(Pipe&& rhs)
{
    std::swap(fds, rhs.fds);
    std::swap(output_closed, rhs.output_closed);
    std::swap(input_closed, rhs.input_closed);
}

Pipe& Pipe::operator=(Pipe&& rhs)
{
    std::swap(fds, rhs.fds);
    std::swap(output_closed, rhs.output_closed);
    std::swap(input_closed, rhs.input_closed);
    return *this;
}

E<Pipe> Pipe::create()
{
    Pipe result;
    if(pipe(result.fds.data()) == 0)
    {
        result.output_closed = false;
        result.input_closed = false;
        return E<Pipe>{std::in_place, std::move(result)};
    }
    else
    {
        return std::unexpected(runtimeError("Failed to create pipe"));
    }
}

Pipe::~Pipe()
{
    if(!input_closed)
    {
        closeInput();
    }
    if(!output_closed)
    {
        closeOutput();
    }
}

E<void> Pipe::closeInput()
{
    if(close(inputFD()) == 0)
    {
        input_closed = true;
        return {};
    }
    else
    {
        return std::unexpected(runtimeError(
            std::string("Failed to close the input end of the pipe: ") +
            strerror(errno)));
    }
}

E<void> Pipe::closeOutput()
{
    if(close(outputFD()) == 0)
    {
        output_closed = true;
        return {};
    }
    else
    {
        return std::unexpected(runtimeError(
            std::string("Failed to close the output end of the pipe: ") +
            strerror(errno)));
    }
}

E<int> Pipe::dupInput(int fd) const
{
    if(int new_fd = dup2(inputFD(), fd); new_fd == -1)
    {
        return std::unexpected(runtimeError(
            std::string("Failed to duplicate input end of pipe: ") +
            strerror(errno)));
    }
    else
    {
        return new_fd;
    }
}

E<int> Pipe::dupOutput(int fd) const
{
    if(int new_fd = dup2(outputFD(), fd); new_fd == -1)
    {
        return std::unexpected(runtimeError(
            std::string("Failed to duplicate output end of pipe: ") +
            strerror(errno)));
    }
    else
    {
        return new_fd;
    }
}

E<std::string> Pipe::read() const
{
    std::array<char, 1024*64> read_buffer;
    ssize_t read_size;
    std::string result;
    while((read_size = ::read(outputFD(), read_buffer.data(),
                              read_buffer.size())) > 0)
    {
        result += std::string(read_buffer.data(), read_size);
    }

    if(read_size == -1)
    {
        return std::unexpected(runtimeError(
            std::string("Failed to read from pipe output: ") +
            strerror(errno)));
    }
    else
    {
        return result;
    }
}

E<void> Pipe::write(std::string_view data) const
{
    size_t offset = 0;
    while(offset < data.size())
    {
        ssize_t written = ::write(inputFD(), data.data() + offset,
                                  data.size() - offset);
        if(written == -1)
        {
            return std::unexpected(runtimeError(
                std::string("Failed to write to pipe: ") +
                strerror(errno)));
        }
        offset += written;
    }
    return {};
}

E<Process> Process::exec(
    const Input input, std::initializer_list<const char*> args,
    const Output output)
{
    Process proc;
    Pipe input_pipe;
    proc.output = output;
    if(std::holds_alternative<std::string_view>(input))
    {
        ASSIGN_OR_RETURN(input_pipe, Pipe::create());
    }
    if(std::holds_alternative<std::string*>(output))
    {
        ASSIGN_OR_RETURN(proc.managed_output_pipe, Pipe::create());
    }

    ASSIGN_OR_RETURN(proc.comm, Pipe::create());

    pid_t pid = fork(); // create child process that is a clone of the parent
    if(pid == 0)       // if pid == 0, then this is the child process
    {
        if(std::holds_alternative<Pipe*>(input))
        {
            Pipe* input_pipe = std::get<Pipe*>(input);
            DO_OR_RETURN(input_pipe->dupOutput(STDIN_FILENO));
            DO_OR_RETURN(input_pipe->closeOutput());
            DO_OR_RETURN(input_pipe->closeInput());
        }
        else if(std::holds_alternative<std::string_view>(input))
        {
            DO_OR_RETURN(input_pipe.dupOutput(STDIN_FILENO));
            DO_OR_RETURN(input_pipe.closeOutput());
            DO_OR_RETURN(input_pipe.closeInput());
        }

        if(std::holds_alternative<Pipe*>(output))
        {
            Pipe* output_pipe = std::get<Pipe*>(output);
            DO_OR_RETURN(output_pipe->dupInput(STDOUT_FILENO));
            // file descriptor no longer needed in child since stdin is a copy.
            DO_OR_RETURN(output_pipe->closeInput());
            // file descriptor unused in child.
            DO_OR_RETURN(output_pipe->closeOutput());
        }
        else if(std::holds_alternative<std::string*>(output))
        {
            DO_OR_RETURN(proc.managed_output_pipe.dupInput(STDOUT_FILENO));
            // file descriptor no longer needed in child since stdin is a copy.
            DO_OR_RETURN(proc.managed_output_pipe.closeInput());
            // file descriptor unused in child.
            DO_OR_RETURN(proc.managed_output_pipe.closeOutput());
        }

        DO_OR_RETURN(proc.comm.closeOutput());

        std::vector<char*> argv(args.size() + 1, nullptr);
        auto args_array = std::data(args);
        for(size_t i = 0; i < args.size(); i++)
        {
            argv[i] = const_cast<char*>(args_array[i]);
        }
        argv.push_back(nullptr);
        if(execvp(argv[0], reinterpret_cast<char* const*>(argv.data())) < 0)
        {
            proc.comm.write("FAIL");
            proc.comm.closeInput();
            exit(1);
        }
        std::unreachable();
    }

    // if we reach here, we are in parent process
    if(std::holds_alternative<Pipe*>(input))
    {
        DO_OR_RETURN(std::get<Pipe*>(input)->closeOutput());
    }
    else if(std::holds_alternative<std::string_view>(input))
    {
        input_pipe.closeOutput();
        input_pipe.write(std::get<std::string_view>(input));
        input_pipe.closeInput();
    }

    if(std::holds_alternative<Pipe*>(output))
    {
        DO_OR_RETURN(std::get<Pipe*>(output)->closeInput());
    }
    else if(std::holds_alternative<std::string*>(output))
    {
        DO_OR_RETURN(proc.managed_output_pipe.closeInput());
    }

    DO_OR_RETURN(proc.comm.closeInput());
    proc.pid = pid;
    return E<Process>{std::in_place, std::move(proc)};
}

Process::Process(Process&& rhs) :
        comm(std::move(rhs.comm)),
        managed_output_pipe(std::move(rhs.managed_output_pipe))
{
    std::swap(pid, rhs.pid);
    std::swap(output, rhs.output);
}

Process& Process::operator=(Process&& rhs)
{
    std::swap(pid, rhs.pid);
    comm = std::move(rhs.comm);
    std::swap(output, rhs.output);
    managed_output_pipe = std::move(rhs.managed_output_pipe);
    return *this;
}

Process::~Process()
{
    if(pid != 0)
    {
        ::kill(pid, SIGKILL);
    }
}

E<int> Process::wait()
{
    int status;
    if(std::holds_alternative<std::string*>(output))
    {
        ASSIGN_OR_RETURN((*std::get<std::string*>(output)),
                         managed_output_pipe.read());
    }
    pid_t wpid = waitpid(pid, &status, 0);
    ASSIGN_OR_RETURN(std::string comm_output, comm.read());
    if(comm_output == "FAIL")
    {
        return std::unexpected(runtimeError("Failed to run command"));
    }
    if(wpid != pid)
    {
        return std::unexpected(runtimeError(
            "Failed to wait for child process"));
    }

    pid = 0;
    if(WIFEXITED(status))
    {
        return WEXITSTATUS(status);
    }
    else if(WIFSIGNALED(status))
    {
        return std::unexpected(runtimeError(std::format(
            "Child process exited by signal {}", WTERMSIG(status))));
    }
    else if(WCOREDUMP(status))
    {
        return std::unexpected(runtimeError("Child process dumped core"));
    }
    else if(WIFSTOPPED(status))
    {
        return std::unexpected(runtimeError(
            std::format("Child process was stopped with signal {}. "
                        "(Was it traced?)", WSTOPSIG(status))));
    }
    else if(WIFCONTINUED(status))
    {
        return std::unexpected(runtimeError(
            "Child process was contined with a SIGCONT."));
    }
    std::unreachable();
}
