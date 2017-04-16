# Jwt Class

Моя попытка сделать аутентификацию с алгоритмом JWT.
Данный класс генерирует, проверяет правильность токена и при валидном токене продлевает время его жизни на заданное время,
а так же извлекает данные из токена.

## как использовать

***Внимание! Класс только генерирует токены, записывать их в куки (или куда-нибудь в другое место) надо самостоятельно!***

```php
// алгоритмы можно передавать любые из списка функции hash_algos()
$jwt = new Jwt('key_string', ['alg' => 'sha256', 'exp' => '+24 hours'], true);

// сгенерировать новый токен
$token = $jwt->token(['uid' => 10]);

// проверить правильность токена и сгенерировать с новым временем жизни
$token = $jwt->validate($token, ['uid' => 10]);

// получить данные из токена
$data = $jwt->data($token);

// получить из токена алгоритм и время жизни
$head_data = $jwt->data($token, true);
```
