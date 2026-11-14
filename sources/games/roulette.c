#include "../headers/types.h"
#include "../headers/terminal.h"
#include "../headers/roulette.h"
#include "../headers/input_manager.h"

// Red numbers in American roulette
static const int32_t red_numbers[] = {
    1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36
};
static const uint32_t red_count = 18;

static uint8_t wait_for_key(void) {
    while (input_manager_has_input()) {
        input_manager_read_scancode();
    }
    
    while (!input_manager_has_input()) {
        __asm__ volatile("pause");
    }
    
    uint8_t scancode = input_manager_read_scancode();
    char ascii = input_manager_scancode_to_ascii(scancode);
    
    return ascii != 0 ? ascii : scancode;
}

static bool is_red(int32_t number) {
    for (uint32_t i = 0; i < red_count; i++) {
        if (red_numbers[i] == number) return true;
    }
    return false;
}

static int32_t spin_wheel(roulette_game_t* game) {
    uint32_t seed = (game->round_number * 1103515245 + 12345 + game->total_spins * 7919);
    seed = (seed * 16807) % 2147483647;
    int32_t result = seed % ROULETTE_NUMBERS;
    if (result == 37) return -1; // 00
    return result;
}

static void draw_separator(void) {
    terminal_write_string("\n");
    for (int i = 0; i < 70; i++) {
        terminal_write_char('=');
    }
    terminal_write_string("\n");
}

static void draw_spinning_animation(int32_t winning_number) {
    // Shows random numbers before landing on the result
    for (int i = 0; i < 12; i++) {
        terminal_clear();
        draw_separator();
        terminal_set_color(14, 0);
        terminal_write_string("\n                 SPINNING THE WHEEL...\n\n");
        terminal_set_color(7, 0);
        
        int32_t display = ((i * 7 + winning_number * 3) % ROULETTE_NUMBERS);
        if (display == 37) display = -1;
        
        terminal_write_string("                      ");
        
        if (display == -1 || display == 0) {
            terminal_set_color(0, 10);
        } else if (is_red(display)) {
            terminal_set_color(15, 12);
        } else {
            terminal_set_color(15, 0);
        }
        
        terminal_write_string("   ");
        if (display == -1) {
            terminal_write_string("00");
        } else if (display < 10) {
            terminal_write_char(' ');
            terminal_write_uint(display);
        } else {
            terminal_write_uint(display);
        }
        terminal_write_string("   ");
        terminal_set_color(7, 0);
        
        terminal_write_string("\n\n");
        draw_separator();
        
        // Delay - gets longer as we near the end
        int32_t delay = (i < 6) ? 200000 : 600000;
        for (volatile int j = 0; j < delay; j++);
    }
    
    terminal_clear();
    draw_separator();
    terminal_set_color(14, 0);
    terminal_write_string("\n                  BALL LANDED ON:\n\n");
    terminal_set_color(7, 0);
    
    terminal_write_string("                      ");
    
    if (winning_number == -1 || winning_number == 0) {
        terminal_set_color(0, 10);
    } else if (is_red(winning_number)) {
        terminal_set_color(15, 12);
    } else {
        terminal_set_color(15, 0);
    }
    
    terminal_write_string("   ");
    if (winning_number == -1) {
        terminal_write_string("00");
    } else if (winning_number < 10) {
        terminal_write_char(' ');
        terminal_write_uint(winning_number);
    } else {
        terminal_write_uint(winning_number);
    }
    terminal_write_string("   ");
    terminal_set_color(7, 0);
    
    terminal_write_string("\n\n");
    draw_separator();
    
    for (volatile int j = 0; j < 1500000; j++);
}

static void draw_number(int32_t number, bool has_bet) {
    if (number == -1) {
        terminal_set_color(10, 0);
        terminal_write_string(" 00");
    } else if (number == 0) {
        terminal_set_color(10, 0);
        terminal_write_string("  0");
    } else {
        if (is_red(number)) {
            terminal_set_color(12, 0);
        } else {
            terminal_set_color(15, 0);
        }
        
        if (number < 10) {
            terminal_write_string("  ");
            terminal_write_uint(number);
        } else {
            terminal_write_string(" ");
            terminal_write_uint(number);
        }
    }
    
    if (has_bet) {
        terminal_set_color(14, 0);
        terminal_write_char('$');
    } else {
        terminal_write_char(' ');
    }
    terminal_set_color(7, 0);
}

static bool has_bet_on_number(roulette_game_t* game, int32_t number) {
    for (uint32_t i = 0; i < game->bet_count; i++) {
        if (game->bets[i].active && game->bets[i].type == ROULETTE_BET_STRAIGHT && 
            game->bets[i].number == number) {
            return true;
        }
    }
    return false;
}

static void draw_table(roulette_game_t* game) {
    terminal_write_string("\n");
    terminal_write_string("  ");
    draw_number(0, has_bet_on_number(game, 0));
    terminal_write_string("  ");
    draw_number(-1, has_bet_on_number(game, -1));
    terminal_write_string("\n\n");
    
    for (int row = 0; row < 3; row++) {
        terminal_write_string("  ");
        for (int col = 0; col < 12; col++) {
            int32_t number = (col * 3) + (3 - row);
            draw_number(number, has_bet_on_number(game, number));
        }
        terminal_write_string("\n");
    }
    terminal_write_string("\n");
}

static void draw_bet_options(roulette_game_t* game) {
    terminal_set_color(11, 0);
    terminal_write_string("BET OPTIONS:\n");
    terminal_set_color(7, 0);
    
    terminal_write_string("  [0-9] Number  ");
    terminal_write_string("[R] Red  ");
    terminal_write_string("[B] Black  ");
    terminal_write_string("[O] Odd  ");
    terminal_write_string("[E] Even\n");
    
    terminal_write_string("  [H] High(19-36)  ");
    terminal_write_string("[L] Low(1-18)  ");
    terminal_write_string("[!/@/#] Dozens\n");
    
    terminal_write_string("\n  [+/-] Bet $5  [Ctrl+] Max Bet  [Ctrl-] Min Bet");
    terminal_write_string("  Amount: $");
    terminal_write_uint(game->current_bet_amount);
    terminal_write_string("\n  [SPACE] Spin  [C] Clear Bets  [ESC] Quit\n");
}

static int32_t calculate_payout(roulette_game_t* game) {
    int32_t winnings = 0;
    
    for (uint32_t i = 0; i < game->bet_count; i++) {
        if (!game->bets[i].active) continue;
        
        bool won = false;
        int32_t payout_multiplier = 0;
        
        switch (game->bets[i].type) {
            case ROULETTE_BET_STRAIGHT:
                if (game->bets[i].number == game->winning_number) {
                    won = true;
                    payout_multiplier = 35;
                }
                break;
                
            case ROULETTE_BET_RED:
                if (game->winning_number > 0 && is_red(game->winning_number)) {
                    won = true;
                    payout_multiplier = 1;
                }
                break;
                
            case ROULETTE_BET_BLACK:
                if (game->winning_number > 0 && !is_red(game->winning_number)) {
                    won = true;
                    payout_multiplier = 1;
                }
                break;
                
            case ROULETTE_BET_ODD:
                if (game->winning_number > 0 && (game->winning_number % 2 == 1)) {
                    won = true;
                    payout_multiplier = 1;
                }
                break;
                
            case ROULETTE_BET_EVEN:
                if (game->winning_number > 0 && (game->winning_number % 2 == 0)) {
                    won = true;
                    payout_multiplier = 1;
                }
                break;
                
            case ROULETTE_BET_HIGH:
                if (game->winning_number >= 19 && game->winning_number <= 36) {
                    won = true;
                    payout_multiplier = 1;
                }
                break;
                
            case ROULETTE_BET_LOW:
                if (game->winning_number >= 1 && game->winning_number <= 18) {
                    won = true;
                    payout_multiplier = 1;
                }
                break;
                
            case ROULETTE_BET_DOZEN1:
                if (game->winning_number >= 1 && game->winning_number <= 12) {
                    won = true;
                    payout_multiplier = 2;
                }
                break;
                
            case ROULETTE_BET_DOZEN2:
                if (game->winning_number >= 13 && game->winning_number <= 24) {
                    won = true;
                    payout_multiplier = 2;
                }
                break;
                
            case ROULETTE_BET_DOZEN3:
                if (game->winning_number >= 25 && game->winning_number <= 36) {
                    won = true;
                    payout_multiplier = 2;
                }
                break;
        }
        
        if (won) {
            winnings += game->bets[i].amount * (payout_multiplier + 1);
        }
    }
    
    return winnings;
}

static void place_bet(roulette_game_t* game, roulette_bet_type_t type, int32_t number) {
    if (game->bet_count >= ROULETTE_MAX_BET_SPOTS) {
        return;
    }
    
    if (game->player_chips < game->current_bet_amount) {
        return;
    }
    
    for (uint32_t i = 0; i < game->bet_count; i++) {
        if (game->bets[i].active && game->bets[i].type == type && 
            game->bets[i].number == number) {
            game->bets[i].amount += game->current_bet_amount;
            game->player_chips -= game->current_bet_amount;
            game->total_bet += game->current_bet_amount;
            game->needs_redraw = true;
            return;
        }
    }
    
    game->bets[game->bet_count].type = type;
    game->bets[game->bet_count].number = number;
    game->bets[game->bet_count].amount = game->current_bet_amount;
    game->bets[game->bet_count].active = true;
    
    game->player_chips -= game->current_bet_amount;
    game->total_bet += game->current_bet_amount;
    game->bet_count++;
    game->needs_redraw = true;
}

static void clear_bets(roulette_game_t* game) {
    for (uint32_t i = 0; i < game->bet_count; i++) {
        if (game->bets[i].active) {
            game->player_chips += game->bets[i].amount;
            game->total_bet -= game->bets[i].amount;
            game->bets[i].active = false;
        }
    }
    game->bet_count = 0;
    game->needs_redraw = true;
}

static void spin_and_resolve(roulette_game_t* game) {
    if (game->bet_count == 0) {
        return;
    }
    
    game->game_state = ROULETTE_STATE_SPINNING;
    
    // Get winning number first
    game->winning_number = spin_wheel(game);
    game->total_spins++;
    game->round_number++;
    
    draw_spinning_animation(game->winning_number);
    
    game->total_won = calculate_payout(game);
    game->player_chips += game->total_won;
    game->total_winnings += (game->total_won - game->total_bet);
    
    game->game_state = ROULETTE_STATE_RESULT;
    game->needs_redraw = true;
}

void roulette_initialize(roulette_game_t* game) {
    game->player_chips = ROULETTE_STARTING_CHIPS;
    game->current_bet_amount = ROULETTE_MIN_BET;
    game->bet_count = 0;
    game->winning_number = 0;
    game->total_bet = 0;
    game->total_won = 0;
    game->game_state = ROULETTE_STATE_BETTING;
    game->round_number = 0;
    game->total_spins = 0;
    game->total_winnings = 0;
    game->selected_bet_type = 0;
    game->selected_number = 0;
    game->needs_redraw = true;
    
    for (uint32_t i = 0; i < ROULETTE_MAX_BET_SPOTS; i++) {
        game->bets[i].active = false;
    }
}

void roulette_render(roulette_game_t* game) {
    if (!game->needs_redraw) return;
    
    terminal_clear();
    
    draw_separator();
    terminal_set_color(14, 0);
    terminal_write_string("             APOLLO ROULETTE CASINO v0.1 (cn ~ buggy)\n");
    terminal_set_color(7, 0);
    draw_separator();
    
    if (game->game_state == ROULETTE_STATE_EXIT) {
        terminal_set_color(12, 0);
        terminal_write_string("\n       Thanks for playing!\n\n");
        terminal_set_color(7, 0);
        terminal_write_string("       Final Stats:\n");
        terminal_write_string("         Total Spins: ");
        terminal_write_uint(game->total_spins);
        terminal_write_string("\n         Total Winnings: $");
        if (game->total_winnings < 0) {
            terminal_write_char('-');
            terminal_write_uint(-game->total_winnings);
        } else {
            terminal_write_uint(game->total_winnings);
        }
        terminal_write_string("\n         Final Chips: $");
        terminal_write_uint(game->player_chips);
        terminal_write_string("\n\n");
        draw_separator();
        game->needs_redraw = false;
        return;
    }
    
    if (game->game_state == ROULETTE_STATE_BETTING) {
        terminal_set_color(11, 0);
        terminal_write_string("Chips: $");
        terminal_write_uint(game->player_chips);
        terminal_set_color(7, 0);
        terminal_write_string("  |  Total Bet: $");
        terminal_write_uint(game->total_bet);
        terminal_write_string("  |  Spins: ");
        terminal_write_uint(game->total_spins);
        terminal_write_string("\n");
        
        draw_table(game);
        draw_bet_options(game);
        
        if (game->bet_count > 0) {
            terminal_write_string("\n  Active Bets:\n");
            for (uint32_t i = 0; i < game->bet_count; i++) {
                if (game->bets[i].active) {
                    terminal_write_string("    $");
                    terminal_write_uint(game->bets[i].amount);
                    terminal_write_string(" on ");
                    
                    switch (game->bets[i].type) {
                        case ROULETTE_BET_STRAIGHT:
                            if (game->bets[i].number == -1) {
                                terminal_write_string("00");
                            } else {
                                terminal_write_uint(game->bets[i].number);
                            }
                            break;
                        case ROULETTE_BET_RED: terminal_write_string("Red"); break;
                        case ROULETTE_BET_BLACK: terminal_write_string("Black"); break;
                        case ROULETTE_BET_ODD: terminal_write_string("Odd"); break;
                        case ROULETTE_BET_EVEN: terminal_write_string("Even"); break;
                        case ROULETTE_BET_HIGH: terminal_write_string("High"); break;
                        case ROULETTE_BET_LOW: terminal_write_string("Low"); break;
                        case ROULETTE_BET_DOZEN1: terminal_write_string("1st Dozen"); break;
                        case ROULETTE_BET_DOZEN2: terminal_write_string("2nd Dozen"); break;
                        case ROULETTE_BET_DOZEN3: terminal_write_string("3rd Dozen"); break;
                    }
                    terminal_write_string("\n");
                }
            }
        }
    } else if (game->game_state == ROULETTE_STATE_RESULT) {
        terminal_set_color(14, 0);
        terminal_write_string("\n            RESULT: ");
        
        if (game->winning_number == -1 || game->winning_number == 0) {
            terminal_set_color(10, 0);
        } else if (is_red(game->winning_number)) {
            terminal_set_color(12, 0);
        } else {
            terminal_set_color(15, 0);
        }
        
        if (game->winning_number == -1) {
            terminal_write_string("00");
        } else {
            terminal_write_uint(game->winning_number);
        }
        
        terminal_set_color(7, 0);
        terminal_write_string(" (");
        if (game->winning_number == -1 || game->winning_number == 0) {
            terminal_set_color(10, 0);
            terminal_write_string("Green");
        } else if (is_red(game->winning_number)) {
            terminal_set_color(12, 0);
            terminal_write_string("Red");
        } else {
            terminal_write_string("Black");
        }
        terminal_set_color(7, 0);
        terminal_write_string(")\n\n");
        
        if (game->total_won > 0) {
            terminal_set_color(10, 0);
            terminal_write_string("            WINNER! ");
            terminal_write_string("+$");
            terminal_write_uint(game->total_won - game->total_bet);
            terminal_write_string("\n\n");
            
            terminal_set_color(7, 0);
            terminal_write_string("            Winning Bets:\n");
            
            for (uint32_t i = 0; i < game->bet_count; i++) {
                if (game->bets[i].active) {
                    bool won = false;
                    int32_t payout = 0;
                    
                    switch (game->bets[i].type) {
                        case ROULETTE_BET_STRAIGHT:
                            if (game->bets[i].number == game->winning_number) {
                                won = true;
                                payout = game->bets[i].amount * 36;
                            }
                            break;
                        case ROULETTE_BET_RED:
                            if (game->winning_number > 0 && is_red(game->winning_number)) {
                                won = true;
                                payout = game->bets[i].amount * 2;
                            }
                            break;
                        case ROULETTE_BET_BLACK:
                            if (game->winning_number > 0 && !is_red(game->winning_number)) {
                                won = true;
                                payout = game->bets[i].amount * 2;
                            }
                            break;
                        case ROULETTE_BET_ODD:
                            if (game->winning_number > 0 && (game->winning_number % 2 == 1)) {
                                won = true;
                                payout = game->bets[i].amount * 2;
                            }
                            break;
                        case ROULETTE_BET_EVEN:
                            if (game->winning_number > 0 && (game->winning_number % 2 == 0)) {
                                won = true;
                                payout = game->bets[i].amount * 2;
                            }
                            break;
                        case ROULETTE_BET_HIGH:
                            if (game->winning_number >= 19 && game->winning_number <= 36) {
                                won = true;
                                payout = game->bets[i].amount * 2;
                            }
                            break;
                        case ROULETTE_BET_LOW:
                            if (game->winning_number >= 1 && game->winning_number <= 18) {
                                won = true;
                                payout = game->bets[i].amount * 2;
                            }
                            break;
                        case ROULETTE_BET_DOZEN1:
                            if (game->winning_number >= 1 && game->winning_number <= 12) {
                                won = true;
                                payout = game->bets[i].amount * 3;
                            }
                            break;
                        case ROULETTE_BET_DOZEN2:
                            if (game->winning_number >= 13 && game->winning_number <= 24) {
                                won = true;
                                payout = game->bets[i].amount * 3;
                            }
                            break;
                        case ROULETTE_BET_DOZEN3:
                            if (game->winning_number >= 25 && game->winning_number <= 36) {
                                won = true;
                                payout = game->bets[i].amount * 3;
                            }
                            break;
                    }
                    
                    if (won) {
                        terminal_write_string("              $");
                        terminal_write_uint(game->bets[i].amount);
                        terminal_write_string(" -> $");
                        terminal_write_uint(payout);
                        terminal_write_string("\n");
                    }
                }
            }
        } else {
            terminal_set_color(12, 0);
            terminal_write_string("            No winners this spin\n");
        }
        
        terminal_set_color(7, 0);
        terminal_write_string("\n            Total Bet: $");
        terminal_write_uint(game->total_bet);
        terminal_write_string("  |  Won: $");
        terminal_write_uint(game->total_won);
        terminal_write_string("\n\n");
        
        terminal_set_color(11, 0);
        terminal_write_string("            Chips: $");
        terminal_write_uint(game->player_chips);
        terminal_set_color(7, 0);
        
        terminal_write_string("\n\n            [SPACE] Play Again  [ESC] Quit\n");
    }
    
    draw_separator();
    game->needs_redraw = false;
}

void roulette_handle_input(roulette_game_t* game, uint8_t key) {
    bool ctrl_pressed = input_manager_is_ctrl_pressed();
    
    if (key == SCANCODE_ESCAPE) {
        game->game_state = ROULETTE_STATE_EXIT;
        game->needs_redraw = true;
        return;
    }
    
    if (game->game_state == ROULETTE_STATE_BETTING) {
        if (ctrl_pressed && (key == '+' || key == '=')) {
            game->current_bet_amount = ROULETTE_MAX_BET;
            game->needs_redraw = true;
            return;
        }
        
        if (ctrl_pressed && (key == '-' || key == '_')) {
            game->current_bet_amount = ROULETTE_MIN_BET;
            game->needs_redraw = true;
            return;
        }
        
        if (key >= '0' && key <= '9') {
            int32_t num = key - '0';
            if (num == 0 && game->selected_number == 0) {
                place_bet(game, ROULETTE_BET_STRAIGHT, 0);
            } else {
                game->selected_number = game->selected_number * 10 + num;
                if (game->selected_number > 36) {
                    game->selected_number = num;
                }
                if (game->selected_number >= 0 && game->selected_number <= 36) {
                    place_bet(game, ROULETTE_BET_STRAIGHT, game->selected_number);
                    game->selected_number = 0;
                }
            }
        } else if (key == 'r' || key == 'R') {
            place_bet(game, ROULETTE_BET_RED, -1);
        } else if (key == 'b' || key == 'B') {
            place_bet(game, ROULETTE_BET_BLACK, -1);
        } else if (key == 'o' || key == 'O') {
            place_bet(game, ROULETTE_BET_ODD, -1);
        } else if (key == 'e' || key == 'E') {
            place_bet(game, ROULETTE_BET_EVEN, -1);
        } else if (key == 'h' || key == 'H') {
            place_bet(game, ROULETTE_BET_HIGH, -1);
        } else if (key == 'l' || key == 'L') {
            place_bet(game, ROULETTE_BET_LOW, -1);
        } else if (key == '!') {
            place_bet(game, ROULETTE_BET_DOZEN1, -1);
        } else if (key == '@') {
            place_bet(game, ROULETTE_BET_DOZEN2, -1);
        } else if (key == '#') {
            place_bet(game, ROULETTE_BET_DOZEN3, -1);
        } else if (key == '+' || key == '=') {
            if (game->current_bet_amount < ROULETTE_MAX_BET) {
                game->current_bet_amount += 5;
                game->needs_redraw = true;
            }
        } else if (key == '-' || key == '_') {
            if (game->current_bet_amount > ROULETTE_MIN_BET) {
                game->current_bet_amount -= 5;
                game->needs_redraw = true;
            }
        } else if (key == 'c' || key == 'C') {
            clear_bets(game);
        } else if (key == ' ') {
            spin_and_resolve(game);
        }
    } else if (game->game_state == ROULETTE_STATE_RESULT) {
        if (key == ' ') {
            game->bet_count = 0;
            game->total_bet = 0;
            game->total_won = 0;
            for (uint32_t i = 0; i < ROULETTE_MAX_BET_SPOTS; i++) {
                game->bets[i].active = false;
            }
            game->game_state = ROULETTE_STATE_BETTING;
            game->needs_redraw = true;
        }
    }
}

void roulette_run(roulette_game_t* game) {
    roulette_initialize(game);
    
    terminal_clear();
    draw_separator();
    terminal_set_color(14, 0);
    terminal_write_string("\n       APOLLO ROULETTE CASINO\n\n");
    terminal_set_color(7, 0);
    terminal_write_string("       Welcome to the roulette table!\n");
    terminal_write_string("       Starting chips: $");
    terminal_write_uint(ROULETTE_STARTING_CHIPS);
    terminal_write_string("\n\n");
    terminal_write_string("       Rules:\n");
    terminal_write_string("         - Straight bet (single number): 35:1\n");
    terminal_write_string("         - Red/Black, Odd/Even, High/Low: 1:1\n");
    terminal_write_string("         - Dozens (1-12, 13-24, 25-36): 2:1\n");
    terminal_write_string("         - 0 and 00 are green (house)\n\n");
    terminal_write_string("       Press any key to begin...\n");
    draw_separator();
    
    wait_for_key();
    
    while (game->game_state != ROULETTE_STATE_EXIT) {
        roulette_render(game);
        
        // Only game over if no chips AND no active bets
        if (game->player_chips <= 0 && game->bet_count == 0) {
            terminal_clear();
            terminal_set_color(12, 0);
            terminal_write_string("\n\n       GAME OVER - Out of chips!\n\n");
            terminal_set_color(7, 0);
            terminal_write_string("       Press ESC to exit\n\n");
            draw_separator();
            wait_for_key();
            game->game_state = ROULETTE_STATE_EXIT;
            break;
        }
        
        uint8_t key = wait_for_key();
        roulette_handle_input(game, key);
    }
    
    if (game->game_state == ROULETTE_STATE_EXIT) {
        roulette_render(game);
    }
}