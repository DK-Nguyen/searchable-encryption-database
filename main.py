import logging
import hydra
from omegaconf import DictConfig, OmegaConf
from tools import get_user_input, create_actors, reset
from database import show_tables
from processes import indexing, file_insertion, search, delete

# A logger for this file
log = logging.getLogger(__name__)


@hydra.main(config_name='config')
def main(cfg: DictConfig):
    # get the path of the project directory as hydra changes the relative paths
    project_dir: str = hydra.utils.get_original_cwd()
    log.info(f"Configurations: \n {OmegaConf.to_yaml(cfg)}")

    run = True
    while run:
        user_input: int = get_user_input()
        if user_input == 0:
            pass
        if user_input == 1:
            reset(cfg, project_dir)
            create_actors(cfg, project_dir)
        if user_input == 2:
            indexing(cfg, project_dir)
        if user_input == 3:
            file_insertion(cfg, project_dir)
        if user_input == 4:
            search_word = input("Enter the word to search: \n")
            search(cfg, project_dir, search_word)
        if user_input == 5:
            delete(cfg, project_dir)
        if user_input == 6:
            show_tables(project_dir, mode="all")
        if user_input == 7:
            run = False


if __name__ == '__main__':
    main()
