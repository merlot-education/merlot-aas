package eu.gaiax.difs.aas.cache.hazelcast;

import java.util.Collection;
import java.util.Map;

import eu.gaiax.difs.aas.cache.DataCache;

public class HazelcastDataCache<K, V> implements DataCache<K, V> {

    @Override
    public void clean() {
        // TODO Auto-generated method stub
        
    }

    @Override
    public V get(K key) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<K, V> getAll() {
        return null;
    }

    @Override
    public Map<K, V> getAll(Collection<? extends K> keys) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void put(K key, V value) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void putAll(Map<? extends K, ? extends V> map) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public void remove(K key) {
        // TODO Auto-generated method stub
        
    }

    @Override
    public long estimatedSize() {
        // TODO Auto-generated method stub
        return 0;
    }

}
