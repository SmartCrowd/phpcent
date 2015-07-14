[![Requirements Status](https://requires.io/github/SmartCrowd/phpcent/requirements.svg?branch=master)](https://requires.io/github/SmartCrowd/phpcent/requirements/?branch=master)

Phpcent
========

Php library to communicate with Centrifuge version above 0.7

Library is published on the Composer: https://packagist.org/packages/sl4mmer/phpcent
```php
{
    "require": {
        "sl4mmer/phpcent":"dev-master",
    }
}
```

Full Centrifuge documentation http://centrifuge.readthedocs.org/en/latest/		

Basic Usage


```php
        
        $client = new \phpcent\Client("http://localhost:8000");
        $client->setProject("projectId","projectSecret");
        $client->publish("basic:main_feed",["message"=>"Hello Everybody"]);
        $history=$client->history("basic:main_feed")];
        
```
All api methods for managing channels has shortends. You can call other methods trough Client::send()
```php
$client->send("namespace_create",["name"=>"newnamespace"])
```

You can use phpcent to create frontend token

```php
	$data['token']=$client->setProject($data["project"],$secret)->buildSign($data["user"].$data["timestamp"]);         
```

        

