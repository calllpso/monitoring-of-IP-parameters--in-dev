Мониторинг параметров IP пакетов на веб-сайте

1) сниффер взят с tcpdump.org, но переписан так, чтобы он захватывал только заголовки IP пакетов и записывал их параметры в соответствющие названиям файлы
2) функция sort высчитывает вероятности всех оригинальных данных каждого параметра и "кладет" в другие файлы
3) функция entropy высчитывает энтропии для каждого параметра
4) по полученным данным должны будут строиться графики при помощи gnuplot
5) html берет полученные графики
6) сервер в планах написать на go
