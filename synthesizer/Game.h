#ifndef SYNTHESIZE_GAME_H
#define SYNTHESIZE_GAME_H

#include <string>
#include <map>
#include "Grammar.h"

class Expression {
public:
    Expression(std::wstring& expr) : m_expression(expr) { }

private:
    std::wstring m_expression;
};

template <typename T1, typename T2>
union Container {

    T1 _t1;
    T2 _t2;
};

class Game {
public:
    Game(Grammar grammar) : m_grammar(grammar) { }
    using production_rule = std::map<NonTerminal, std::vector<Container<NonTerminal, Terminal>>>;
    void init_transformation_rules();
    void init_variables();
    /**
     * Evaluate an expression.
     * @param expr the expression to be evaluated.
     * @return evaluated value.
     */
    double evaluated_expression(Expression& expr);
    bool is_terminal(Expression& expr);

private:
    Grammar m_grammar;
};


#endif //SYNTHESIZE_GAME_H
