<?php

class originating_ip extends rcube_plugin
{
    public function init()
    {
        $this->add_hook('storage_connect', [$this, 'storage_connect']);
    }

    public function storage_connect($args)
    {
        $args['preauth_ident'] = ['x-originating-ip' => rcube_utils::remote_addr()];

        return $args;
    }
}
