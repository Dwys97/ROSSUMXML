#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting development environment...${NC}"

# Run the VS Code task
code --remote-terminal-wait -e "workbench.action.tasks.runTask" "Start Development Environment"

# Убиваем существующую сессию, если она есть
tmux kill-session -t rossumxml 2>/dev/null

# Создаем новую сессию
tmux new-session -d -s rossumxml

# Создаем окна для каждого сервиса
tmux rename-window -t rossumxml:0 'Database'
tmux send-keys -t rossumxml:0 'docker-compose logs -f db' C-m

tmux new-window -t rossumxml:1 -n 'Backend'
tmux send-keys -t rossumxml:1 'cd backend && sam local start-api --docker-network rossumxml_default --port 3000' C-m

tmux new-window -t rossumxml:2 -n 'Frontend'
tmux send-keys -t rossumxml:2 'cd frontend && npm run dev' C-m

# Разделяем окно на панели
tmux select-layout -t rossumxml tiled

# Присоединяемся к сессии
echo -e "${GREEN}Все сервисы запущены в tmux сессии!${NC}"
echo -e "${GREEN}Для просмотра всех сервисов выполните: tmux attach -t rossumxml${NC}"
echo -e "${BLUE}Подсказка: Ctrl+b d - отключиться от tmux${NC}"
echo -e "${BLUE}Подсказка: Ctrl+b + стрелки - переключение между панелями${NC}"

# Присоединяемся к сессии
tmux attach -t rossumxml

# Функция для корректного завершения
cleanup() {
    echo -e "${BLUE}\nЗавершение работы...${NC}"
    docker-compose down
    exit 0
}

# Перехватываем сигнал завершения
trap cleanup SIGINT SIGTERM