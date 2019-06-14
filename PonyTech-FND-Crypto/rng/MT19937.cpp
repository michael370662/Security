#include <PonyTech-FND-Crypto/rng/MT19937.hpp>
#include <PonyTech-LowLevel-Basic/PonyTech-LowLevel-Basic.h>

BEGIN_NAMESPACE(FND)
BEGIN_NAMESPACE(Crypto)

//------------------------------------
// thread instance
//------------------------------------
BEGIN_NAMESPACE()
class Instance : public AbstractThreadSingleton 
{
    FND_THREAD_SINGLETON(Instance);
public:
    MT19937 rng;

private:
    FND_DISABLE_COPY(Instance);
};

Instance::Instance() { rng.seed(basic_system_random_value());}
Instance::~Instance() {}


END_NAMESPACE()


static constexpr uint32_t k_seed_magic = 0x6c078965;
static constexpr uint32_t k_gen_magic = 0x9908b0df;

MT19937::MT19937()
{    
    seed(0);
}

MT19937::~MT19937()
{   
}

MT19937& MT19937::get() 
{
    return ThreadSingletonSystem::instance<Instance>()->rng;
}

void MT19937::seed(uint32_t seed_val)
{
    m_state[0] = seed_val;
    for(size_t i=1; i<k_size; i++)
    {
        m_state[i] = k_seed_magic * (m_state[i-1] ^ (m_state[i-1] >> 30)) + i;
    }
    m_current_index = k_size;
}

static uint32_t unroll(uint32_t state1, uint32_t state2, uint32_t seed)
{
    uint32_t y = (state1 & 0x800000000) | (state2 & (0x80000000 - 1));
    return seed ^ (y >> 1) ^ ((~(y & 0x1)+1) & k_gen_magic);
}

void MT19937::generate() 
{
    for(size_t i=0; i<k_size - k_period; i++)
    {
        m_state[i] = unroll(m_state[i], m_state[i+1], m_state[i+k_period]);
    }
    for(size_t i=k_size-k_period; i<k_size-1; i++)
    {
        m_state[i] = unroll(m_state[i], m_state[i+1], m_state[i-k_size+k_period]);        
    }
    m_state[k_size-1] = unroll(m_state[k_size-1], m_state[0], m_state[k_period-1]);        
    
    for(size_t i=0; i<k_size; i++)
    {   
        auto y = m_state[i];
        y ^= y >> 11;
        y ^= y << 7  & 0x9d2c5680;
        y ^= y << 15 & 0xefc60000;
        y ^= y >> 18;
        m_tempered[i] = y;
    }
    m_current_index = 0;
}

uint32_t MT19937::random()
{   
    if (m_current_index >= k_size) generate();
    return m_tempered[m_current_index++];
}

uint32_t MT19937::random(uint32_t min_val, uint32_t max_val)
{
    auto interval = max_val - min_val + 1;
    auto val = random();
    return min_val + (val % interval);
}

int32_t MT19937::random(int32_t  min_val, int32_t  max_val)
{
    auto interval = max_val - min_val + 1;
    auto val = random();
    return min_val + (val % interval);
}

void MT19937::random(void *data, size_t cnt)
{
    char* ptr = static_cast<char*>(data);
    char* end = ptr + cnt;

    while(ptr < end)
    {
        auto unit = Misc::minimum(static_cast<size_t>(end-ptr), (k_size - m_current_index) * sizeof(uint32_t));
        MemoryAction::copy(ptr, m_state+ m_current_index, unit);

        ptr += unit;
        m_current_index += (unit + sizeof(uint32_t) -1) / sizeof(uint32_t);
        if (m_current_index >= k_size) generate();
    }
}


END_NAMESPACE(Crypto)
END_NAMESPACE(FND)
