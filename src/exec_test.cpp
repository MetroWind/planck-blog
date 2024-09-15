#include <gtest/gtest.h>

#include "exec.hpp"
#include "error.hpp"
#include "utils.hpp"
#include "test_utils.hpp"

TEST(Exec, CanPipeWithPipes)
{
    ASSIGN_OR_FAIL(Pipe input, Pipe::create());
    ASSIGN_OR_FAIL(auto output_pipe, Pipe::create());
    ASSIGN_OR_FAIL(auto proc, Process::exec(&input, {"cat",}, &output_pipe));
    EXPECT_TRUE(isExpected(input.write("aaa")));
    EXPECT_TRUE(isExpected(input.closeInput()));
    ASSIGN_OR_FAIL(std::string output, output_pipe.read());
    EXPECT_TRUE(isExpected(output_pipe.closeOutput()));
    EXPECT_EQ(output, "aaa");
    ASSIGN_OR_FAIL(int status, proc.wait());
    EXPECT_EQ(status, 0);
}

TEST(Exec, CanPipeWithString)
{
    std::string output;
    ASSIGN_OR_FAIL(auto proc, Process::exec("aaa", {"cat",}, &output));
    ASSIGN_OR_FAIL(int status, proc.wait());
    EXPECT_EQ(output, "aaa");
    EXPECT_EQ(status, 0);
}

// TODO: Using a Pipe to connect two Processes doesn’t work yet... I
// think it might be that when the parent forks the 2nd child, the 1st
// child has not done setting up the pipes yet. I might need to let
// the parent process wait for the child to setup the pipes before
// continuing after fork. So I need some kind of sync between the
// child and the parent. I could use shared mem or message queue to do
// this. Also might need to remove the kill() in the destructor to
// make this worl.
TEST(DISABLED_Exec, CanPipeBetweenProcs)
{
    std::string output;
    ASSIGN_OR_FAIL(Pipe ipc, Pipe::create());
    ASSIGN_OR_FAIL(Process proc1, Process::exec("bbb\naaa", {"cat",}, &ipc));
    ASSIGN_OR_FAIL(Process proc2, Process::exec(&ipc, {"sort",}, &output));
    ASSIGN_OR_FAIL(int status1, proc1.wait());
    ASSIGN_OR_FAIL(int status2, proc2.wait());
    EXPECT_EQ(output, "aaa\nbbb");
    EXPECT_EQ(status1, 0);
    EXPECT_EQ(status2, 0);
}

TEST(Exec, WillFailWithInvalidCmd)
{
    ASSIGN_OR_FAIL(Pipe input, Pipe::create());
    ASSIGN_OR_FAIL(auto output_pipe, Pipe::create());
    ASSIGN_OR_FAIL(auto proc,
                   Process::exec(&input, {"fjdkal",}, &output_pipe));
    EXPECT_FALSE(isExpected(proc.wait()));
}
