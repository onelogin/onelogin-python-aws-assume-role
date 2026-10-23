"""
Reads the user's answers to the CLI prompts.
"""

import sys


def read_line():
    """
    Reads the answer to a prompt. Exits once input runs out, since the callers
    re-prompt until they get a valid answer and would otherwise loop forever.
    """
    line = sys.stdin.readline()
    if not line:
        sys.exit("\nNo input to answer the prompt above: stdin reached end of file.")
    return line.strip()


def get_yes_or_not():
    answer = None
    while (answer != 'y' and answer != 'n'):
        answer = read_line().lower()
    return answer


def get_selection(max):
    answer = None
    while (answer is None or type(answer) != int or answer not in range(0, max)):
        answer = read_line()
        try:
            answer = int(answer)
        except:
            pass
    return answer


def get_duration():
    answer = None
    while (answer is None or type(answer) != int or answer not in range(900, 43200)):
        answer = read_line()
        try:
            answer = int(answer)
        except:
            pass
    return answer


def ask_iteration_new_user():
    print("\nDo you want to select a new user?  (y/n)")
    answer = get_yes_or_not()
    if answer == 'y':
        return True
    else:
        sys.exit()
