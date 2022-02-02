## HTTP сервер для работы с сигнализацией StarLine
Прокси для некоторых методов API из https://developer.starline.ru

### Запуск сервиса
#### Непосредственно 
`python main.py`
#### Docker
`docker build -t starline-api-proxy .`\
`docker run -p 2307:2307 starline-api-proxy`


### Порядок работы с сервисом
1. Получить `appId` и `appSecret` в https://my.starline.ru/developer
2. Получить `userId` и `slidToken`: \
`GET http://localhost:2307/application/slidToken?appId={appId}&appSecret={appSecret}&login={login}&password={password}` \
При двухфакторной авторизации потребуется повторный запрос с добавлением `&smsCode={smsCode}`
3. Получить `deviceId` нужного устройства: \
`GET http://localhost:2307/user/{userId}/devices?slidToken={slidToken}` 

### Методы
* `GET http://localhost:2307/device/{deviceId}/data` - информация об состоянии устройства
