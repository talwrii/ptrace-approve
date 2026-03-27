# ptrace-approve
Trace system calls and manually approve them or create rules to match them.

This is ai-generated unreviewed code. I have used it a coouple of times.

## Caveats
AI-generated code, unreviewed, *slow*

## Motivation
I wanted to rub some vibe coded apps over my code and not have it destroy my code.

## Alternatives and prior work
This is influenced form a UI perspective by cluade code, where you approve individual commands.
It uses ptrace and apparmor does similar things. Apparmore is faster, and can record rules to allow - but not does not have this sort of real time approval.

This use the `python-pytrace` library which does all the fiddly work.

Tools like austral can place limits at the module or functions using typeu systems.

## Installation
pipx install ptrace-approve

## Usage
ptrace-approve app

By default all reads are allowed.

Individually approve rules or add patterns. `.` in patterns does not match ,'s or brackets. Use `(.|[.(),])` for the conventional meaning of . in regexps

the abolsute path to app app is found and a default profile is stored for the app based on this path.

ptrace-approve --clear app
